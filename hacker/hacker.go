package hacker

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/ec2"
	cf "github.com/crewjam/go-cloudformation"
	"github.com/opsee/basic/schema"
	opsee_aws_ec2 "github.com/opsee/basic/schema/aws/ec2"
	"github.com/opsee/basic/service"
	log "github.com/opsee/logrus"
	opsee_types "github.com/opsee/protobuf/opseeproto/types"
)

const (
	MaxStackUpdateErrorCount = 3
	DefaultResponseCacheTTL  = 2 * time.Minute
	BezosRequestTimeout      = 30 * time.Second
)

var (
	signalsChannel = make(chan os.Signal, 1)
)

func init() {
	signal.Notify(signalsChannel, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
}

func Session(region string, creds *credentials.Credentials) *session.Session {
	sess := session.New(&aws.Config{
		Credentials: creds,
		Region:      aws.String(region),
	})

	return sess
}

type Hacker struct {
	CustomerId                  string
	Region                      string
	VpcId                       string
	HostSecurityGroupPhysicalId string
	ingressStackPhysicalId      string
	bastionStackPhysicalId      string
	waitTime                    time.Duration
	stackTimeoutMinutes         int64
	ec2Client                   *ec2.EC2
	bezosClient                 service.BezosClient
	cloudformationClient        *cloudformation.CloudFormation
	quit                        chan string
	kill                        chan bool
	bastionState                *schema.BastionState
	waitGroup                   *sync.WaitGroup
	stackUpdateErrCount         int
	securityGroups              []*opsee_aws_ec2.SecurityGroup
	updated                     bool
}

func NewHacker(bastion *schema.BastionState, creds *credentials.Credentials, quitChan chan string, bc service.BezosClient) (*Hacker, error) {
	if bastion == nil {
		return nil, fmt.Errorf("Nil bastion argument")
	}
	hacker := &Hacker{
		CustomerId:             bastion.CustomerId,
		Region:                 bastion.Region,
		bastionStackPhysicalId: fmt.Sprintf("opsee-stack-%s", bastion.CustomerId),
		waitTime:               time.Duration(time.Minute * 2),
		stackTimeoutMinutes:    int64(2),
		quit:                   quitChan,
		kill:                   make(chan bool),
		waitGroup:              &sync.WaitGroup{},
		bezosClient:            bc,
		updated:                true,
	}

	sess := Session(bastion.Region, creds)
	hacker.VpcId = bastion.VpcId
	hacker.ec2Client = ec2.New(sess)
	hacker.cloudformationClient = cloudformation.New(sess)

	err := hacker.FindIngressStack()
	if err != nil {
		return nil, err
	}

	return hacker, hacker.Validate()
}

func (h *Hacker) FindIngressStack() error {
	// get security group id, group name, from bastion cloudformation stack
	params := &cloudformation.DescribeStackResourcesInput{
		StackName: aws.String(h.bastionStackPhysicalId),
	}

	resp, err := h.cloudformationClient.DescribeStackResources(params)
	if err != nil {
		return err
	}

	for _, resource := range resp.StackResources {
		switch *resource.LogicalResourceId {
		case "OpseeSecurityGroup":
			h.HostSecurityGroupPhysicalId = *resource.PhysicalResourceId
		case "OpseeBastionIngressStack":
			h.ingressStackPhysicalId = *resource.PhysicalResourceId

			// try to avoid creating a hacker for customers who's stacks have been updated by the legacy hacker
			if aws.StringValue(resource.ResourceStatus) == "CREATE_COMPLETE" || aws.StringValue(resource.ResourceStatus) == "UPDATE_COMPLETE" {
				if time.Now().UTC().Sub(aws.TimeValue(resource.Timestamp)) <= time.Duration(2*time.Minute) {
					return fmt.Errorf("Stack was recently updated.  Last updated: %s", aws.TimeValue(resource.Timestamp).String())
				}
			} else {
				return fmt.Errorf("Stack in incorrect state: %s.  Last updated: %s", aws.StringValue(resource.ResourceStatus), aws.TimeValue(resource.Timestamp).String())
			}
		}
	}

	return nil
}

// Ensures hacker has required fields retrieved from cfn and env.
func (h *Hacker) Validate() error {
	missing := []string{}
	if h.CustomerId == "" {
		missing = append(missing, "CustomerId")
	}
	if h.HostSecurityGroupPhysicalId == "" {
		missing = append(missing, "HostSecurityGroupPhysicalId")
	}
	if h.ingressStackPhysicalId == "" {
		missing = append(missing, "ingressStackPhysicalId")
	}
	if h.bastionStackPhysicalId == "" {
		missing = append(missing, "bastionStackPhysicalId")
	}

	if len(missing) > 0 {
		return fmt.Errorf("Struct missing, %s", strings.Join(missing, ", "))
	}

	return nil
}

// Used to update users ingress stack
func (h *Hacker) UpdateStack(stackName string, parameters []*cloudformation.Parameter, templateBody string) error {
	log.WithFields(log.Fields{"CustomerId": h.CustomerId, "Parameters": parameters, "StackName": stackName, "TemplateBody": templateBody}).Debugf("Attempting to update stack.")
	updateStackInput := &cloudformation.UpdateStackInput{
		Capabilities: []*string{aws.String("CAPABILITY_IAM")},
		Parameters:   parameters,
		StackName:    aws.String(stackName),
		TemplateBody: aws.String(templateBody),
	}

	resp, err := h.cloudformationClient.UpdateStack(updateStackInput)
	log.WithFields(log.Fields{"CustomerId": h.CustomerId, "Response": resp, "Error": err}).Debugf("Received response from cloudformation.")
	if err != nil {
		h.handleStackUpdateError(err)
		return err
	}

	err = h.cloudformationClient.WaitUntilStackUpdateComplete(&cloudformation.DescribeStacksInput{
		StackName: aws.String(stackName),
	})
	if err != nil {
		log.WithFields(log.Fields{"CustomerId": h.CustomerId}).WithError(err).Error("Waiting on stack update failed.")
	}

	return err
}

// call stop if the stack is in state DELETE_COMPLETE or DELETE_IN_PROGRESS.  save an API call
func (h *Hacker) handleStackUpdateError(err error) {
	awsErr, ok := err.(awserr.RequestFailure)
	if ok && awsErr.Code() == "ValidationError" {
		if strings.Contains(awsErr.Message(), "No updates are to be performed.") {
			return
		}
		// if the stack has been deleted, stop trying to
		if strings.Contains(awsErr.Message(), "DELETE_COMPLETE") || strings.Contains(awsErr.Message(), "DELETE_IN_PROGESS") {
			go h.Stop()
			return
		}
		h.stackUpdateErrCount += 1
	}
	if h.stackUpdateErrCount >= MaxStackUpdateErrorCount {
		log.WithFields(log.Fields{"CustomerId": h.CustomerId}).Warn("Max stack update error count reached")
		go h.Stop()
	}
}

func (h *Hacker) updateSecurityGroups() (bool, error) {
	input := &opsee_aws_ec2.DescribeSecurityGroupsInput{
		Filters: []*opsee_aws_ec2.Filter{
			&opsee_aws_ec2.Filter{
				Name:   aws.String("vpc-id"),
				Values: []string{h.VpcId},
			},
		},
	}

	timestamp := &opsee_types.Timestamp{}
	timestamp.Scan(time.Now().UTC().Add(DefaultResponseCacheTTL * -1))
	ctx, _ := context.WithTimeout(context.Background(), BezosRequestTimeout)
	resp, err := h.bezosClient.Get(
		ctx,
		&service.BezosRequest{
			User: &schema.User{
				Id:         1,
				CustomerId: h.CustomerId,
				Email:      "thisisnotarealemailaddress",
				Verified:   true,
				Active:     true,
				Admin:      false,
			},
			Region: h.Region,
			VpcId:  h.VpcId,
			MaxAge: nil, // don't cache
			Input:  &service.BezosRequest_Ec2_DescribeSecurityGroupsInput{input},
		})
	if err != nil {
		return false, err
	}

	output := resp.GetEc2_DescribeSecurityGroupsOutput()
	if output == nil {
		return false, fmt.Errorf("error decoding aws response")
	}

	securityGroups := output.SecurityGroups
	if len(securityGroups) != len(h.securityGroups) {
		h.securityGroups = securityGroups
		return true, nil
	}

	// TODO(dan) Think about ChangeSets instead of this hack.
	newGroups := make(map[string]int)
	forceUpdate := false
	for i, securityGroup := range securityGroups {
		for _, tag := range securityGroup.Tags {
			if aws.StringValue(tag.Key) == "opsee_disable_ingress" {
				if aws.StringValue(tag.Value) == "true" {
					forceUpdate = true
					continue
				}
			}
		}
		newGroups[aws.StringValue(securityGroup.GroupId)] = i
	}

	for _, securityGroup := range h.securityGroups {
		if _, ok := newGroups[aws.StringValue(securityGroup.GroupId)]; !ok || forceUpdate {
			log.WithFields(log.Fields{"CustomerId": h.CustomerId, "GroupId": securityGroup.GroupId}).Error("Found new security group. Updating stack.")
			h.securityGroups = securityGroups
			return true, nil
		}
	}
	log.WithFields(log.Fields{"CustomerId": h.CustomerId}).Info("No updates are to be performed.")

	return false, nil
}

// Generate json for current ingress template
func (h *Hacker) GenerateIngressTemplateJSON() ([]byte, error) {
	template := cf.NewTemplate()
	template.Description = "Listing of bastion security-group ingress rules."
	template.Parameters["BastionSecurityGroupId"] = &cf.Parameter{
		Description: "Bastion's security group id.",
		Type:        "String",
	}

	for i, securityGroup := range h.securityGroups {
		resourceName := fmt.Sprintf("OpseeIngressRule%d", i)
		template.AddResource(resourceName, cf.EC2SecurityGroupIngress{
			IpProtocol:            cf.String("tcp"),
			FromPort:              cf.Integer(0),
			ToPort:                cf.Integer(65535),
			SourceSecurityGroupId: cf.Ref("BastionSecurityGroupId").String(),
			GroupId:               cf.String(*securityGroup.GroupId),
		})
	}

	return json.Marshal(template)
}

// Get security groups from bezos, store them, and add ingress rules if necessary
func (h *Hacker) Hack() error {
	// if the last update didn't fail, fetch security groups
	if h.updated {
		cng, err := h.updateSecurityGroups()
		if err != nil {
			log.WithFields(log.Fields{"CustomerId": h.CustomerId, "err": err}).Warn("Couldn't retrieve security groups")
			return nil
		}

		// No updates to be performed
		if cng == false {
			return nil
		}
	}
	h.updated = false

	parameters := []*cloudformation.Parameter{
		&cloudformation.Parameter{
			ParameterKey:   aws.String("BastionSecurityGroupId"),
			ParameterValue: aws.String(h.HostSecurityGroupPhysicalId),
		},
	}

	tl, err := h.GenerateIngressTemplateJSON()
	if err != nil {
		log.WithFields(log.Fields{"CustomerId": h.CustomerId, "err": err}).Error("Couldn't generate ingress template.")
		return err
	}

	err = h.UpdateStack(h.ingressStackPhysicalId, parameters, string(tl))
	if err != nil {
		return err
	}
	h.updated = true

	return nil
}

func (h *Hacker) Stop() {
	close(h.kill)
	h.waitGroup.Wait()
	h.quit <- h.CustomerId
}

func (h *Hacker) HackForever() {
	h.waitGroup.Add(1)
	defer h.waitGroup.Done()
	log.WithFields(log.Fields{"CustomerId": h.CustomerId}).Info("Started hacker.")
	for {
		t := time.Now()
		log.WithFields(log.Fields{"customer_id": h.CustomerId}).Info("Hacking")
		err := h.Hack()
		if err != nil {
			log.WithFields(log.Fields{"CustomerId": h.CustomerId}).WithError(err).Error("Couldn't update the stack.")
		}
		if wait := h.waitTime - time.Since(t); wait > time.Millisecond {
			log.Info("Waiting ", wait)
			select {
			case <-h.kill:
				log.WithFields(log.Fields{"CustomerId": h.CustomerId}).Info("Exiting.")
				return
			case <-time.After(wait):
				continue
			}
		}
	}
}
