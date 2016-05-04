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

	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudformation"
	"github.com/aws/aws-sdk-go/service/ec2"
	cf "github.com/crewjam/go-cloudformation"
	"github.com/opsee/basic/schema"
)

const (
	MaxStackUpdateErrorCount = 3
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
	HostSecurityGroupPhysicalId string
	VpcId                       string
	ingressStackPhysicalId      string
	bastionStackPhysicalId      string
	waitTime                    time.Duration
	stackTimeoutMinutes         int64
	ec2Client                   *ec2.EC2
	cloudformationClient        *cloudformation.CloudFormation
	quit                        chan string
	kill                        chan bool
	waitGroup                   *sync.WaitGroup
	stackUpdateErrCount         int
}

func NewHacker(bastion *schema.BastionState, creds *credentials.Credentials, quitChan chan string) (*Hacker, error) {
	if bastion == nil {
		return nil, fmt.Errorf("Nil bastion argument")
	}
	hacker := &Hacker{
		CustomerId:             bastion.CustomerId,
		bastionStackPhysicalId: fmt.Sprintf("opsee-stack-%s", bastion.CustomerId),
		waitTime:               time.Duration(time.Minute * 2),
		stackTimeoutMinutes:    int64(2),
		quit:                   quitChan,
		kill:                   make(chan bool),
		waitGroup:              &sync.WaitGroup{},
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

// Returns a list of security groups for the hacker's instances vpc
func (h *Hacker) GetSecurityGroups() ([]*ec2.SecurityGroup, error) {
	output, err := h.ec2Client.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		Filters: []*ec2.Filter{
			{
				Name:   aws.String("vpc-id"),
				Values: []*string{aws.String(h.VpcId)},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	return output.SecurityGroups, err
}

// Returns a stack template body
func (h *Hacker) GetStackTemplateBody(stackName string) (*string, error) {
	output, err := h.cloudformationClient.GetTemplate(&cloudformation.GetTemplateInput{StackName: aws.String(stackName)})
	if err != nil {
		return nil, err
	}
	return output.TemplateBody, err
}

func (h *Hacker) UpdateStack(stackName string, parameters []*cloudformation.Parameter, templateBody string) error {
	log.WithFields(log.Fields{"CustomerId": h.CustomerId}).Infof("Attempting to update stack  %s", stackName)
	updateStackInput := &cloudformation.UpdateStackInput{
		Capabilities: []*string{aws.String("CAPABILITY_IAM")},
		Parameters:   parameters,
		StackName:    aws.String(stackName),
		TemplateBody: aws.String(templateBody),
	}

	_, err := h.cloudformationClient.UpdateStack(updateStackInput)
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
	h.stackUpdateErrCount += 1
	if h.stackUpdateErrCount >= MaxStackUpdateErrorCount {
		log.WithFields(log.Fields{"CustomerId": h.CustomerId}).Warn("Max stack update error count reached")
		go h.Stop()
	} else if ok && awsErr.Code() == "ValidationError" {
		// if the stack has been deleted, stop trying to
		if strings.Contains(awsErr.Message(), "DELETE_COMPLETE") || strings.Contains(awsErr.Message(), "DELETE_IN_PROGESS") {
			go h.Stop()
		}
	}
}

func (h *Hacker) Hack() error {
	securityGroups, err := h.GetSecurityGroups()
	if err != nil {
		log.WithFields(log.Fields{"CustomerId": h.CustomerId}).WithError(err).Error("Couldn't retrieve security groups")
		return err
	}

	template := cf.NewTemplate()
	template.Description = "Listing of bastion security-group ingress rules."
	template.Parameters["BastionSecurityGroupId"] = &cf.Parameter{
		Description: "Bastion's security group id.",
		Type:        "String",
	}

	parameters := []*cloudformation.Parameter{
		&cloudformation.Parameter{
			ParameterKey:   aws.String("BastionSecurityGroupId"),
			ParameterValue: aws.String(h.HostSecurityGroupPhysicalId),
		},
	}

	//TODO(dan) use bezosphere
	for i, securityGroup := range securityGroups {
		log.WithFields(log.Fields{"CustomerId": h.CustomerId}).Debugf("Adding security Group: ", *securityGroup.GroupId)
		resourceName := fmt.Sprintf("OpseeIngressRule%d", i)
		template.AddResource(resourceName, cf.EC2SecurityGroupIngress{
			IpProtocol:            cf.String("tcp"),
			FromPort:              cf.Integer(0),
			ToPort:                cf.Integer(65535),
			SourceSecurityGroupId: cf.Ref("BastionSecurityGroupId").String(),
			GroupId:               cf.String(*securityGroup.GroupId),
		})
	}

	templateBody, err := json.MarshalIndent(template, "", "  ")
	if err != nil {
		log.WithError(err).Error("Failed to marshal template body.")
		return err
	}

	err = h.UpdateStack(h.ingressStackPhysicalId, parameters, string(templateBody))
	if err != nil {
		log.WithFields(log.Fields{"CustomerId": h.CustomerId}).WithError(err).Error("Failed to update stack.")
		return err
	}

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
