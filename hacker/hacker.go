package hacker

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/context"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
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
	ErrorKillThreshold      = 3
	DefaultResponseCacheTTL = 2 * time.Minute
	BezosRequestTimeout     = 30 * time.Second
	StackTimeout            = 2 * time.Minute
	IgnoreIngressKey        = "opsee_disable_ingress"
	IngnoreIngressValue     = "true"
	HoldTime                = 2 * time.Minute
)

var (
	signalsChannel = make(chan os.Signal, 1)
)

func init() {
	signal.Notify(signalsChannel, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
}

type Config struct {
	CustomerId string
	Region     string
	VpcId      string
}

// returns err if config is missing fields
func (c *Config) Validate() error {
	missing := []string{}
	if c.CustomerId == "" {
		missing = append(missing, "CustomerId")
	}
	if c.Region == "" {
		missing = append(missing, "Region")
	}
	if c.VpcId == "" {
		missing = append(missing, "VpcId")
	}

	if len(missing) > 0 {
		return fmt.Errorf("Struct missing, %s", strings.Join(missing, ", "))
	}

	return nil
}

type Clients struct {
	Ec2            *ec2.EC2
	Bezos          *service.Bezos
	Cloudformation *cloudformation.CloudFormation
}

// returns err if clients is missing fields
func (c *Clients) Validate() error {
	missing := []string{}
	if c.Bezos == nil {
		missing = append(missing, "")
	}
	if c.Ec2 == nil {
		missing = append(missing, "ec2 client")
	}
	if c.Cloudformation == nil {
		missing = append(missing, "cloudformation client")
	}

	if len(missing) > 0 {
		return fmt.Errorf("Struct missing, %s", strings.Join(missing, ", "))
	}

	return nil
}

type Resources struct {
	BastionStackPhysicalId      string
	HostSecurityGroupPhysicalId string
	IngressStackPhysicalId      string
}

// returns err if resources is missing fields
func (r *Resources) Validate() error {
	missing := []string{}
	if r.BastionStackPhysicalId == "" {
		missing = append(missing, "BastionStackPhysicalId")
	}
	if r.HostSecurityGroupPhysicalId == "" {
		missing = append(missing, "HostSecurityGroupPhysicalId")
	}
	if r.IngressStackPhysicalId == "" {
		missing = append(missing, "IngressStackPhysicalId")
	}

	if len(missing) > 0 {
		return fmt.Errorf("Struct missing, %s", strings.Join(missing, ", "))
	}

	return nil
}

type Hacker struct {
	config    *Config
	clients   *Clients
	resources *Resources
	quit      chan string
	kill      chan bool
	waitGroup *sync.WaitGroup
	errCount  int
}

// returns pertinent log fields
func (h *Hacker) Fields() log.Fields {
	return log.Fields{"customer_id": c.CustomerId, "errCount": h.errCount}
}

// returns err if hacker is missing fields
func (h *Hacker) Validate() error {
	if h.conig == nil {
		return fmt.Errorf("missing config")
	} else {
		if err := h.config.Validate(); err != nil {
			return err
		}
	}
	if h.Resources != nil {
		return fmt.Errorf("missing resources")
	} else {
		if err := h.resources.Validate(); err != nil {
			return err
		}
	}
	if h.clients != nil {
		return fmt.Errorf("missing clients")
	} else {
		if err := h.clients.Validate(); err != nil {
			return err
		}
	}

	return nil
}

func New(config *Config, resources *Resources, clients *Clients, quitChan chan string) (*Hacker, error) {
	hacker := &Hacker{
		config:    config,
		resources: resources,
		clients:   clients,
		quit:      quitChan,
		kill:      make(chan bool),
		waitGroup: &sync.WaitGroup{},
		updated:   true,
	}

	params := &cloudformation.DescribeStackResourcesInput{
		StackName: aws.String(h.Resources.BastionStackPhysicalId),
	}
	resp, err := h.Clients.Cloudformation.DescribeStackResources(params)
	if err != nil {
		return err
	}

	for _, resource := range resp.StackResources {
		switch *resource.LogicalResourceId {
		case "OpseeSecurityGroup":
			h.Resources.HostSecurityGroupPhysicalId = aws.StringValue(resource.PhysicalResourceId)
		case "OpseeBastionIngressStack":
			h.Resources.IngressStackPhysicalId = aws.StringValue(resource.PhysicalResourceId)
		}
	}

	return hacker, hacker.Validate()
}

func (h *Hacker) UpdateIngressStack(templateBody string) error {
	log.WithFields(h.Fields()).Debugf("Attempting to update stack.")
	parameters := []*cloudformation.Parameter{
		&cloudformation.Parameter{
			ParameterKey:   aws.String("BastionSecurityGroupId"),
			ParameterValue: aws.String(h.Resources.HostSecurityGroupPhysicalId),
		},
	}

	updateStackInput := &cloudformation.UpdateStackInput{
		Capabilities: []*string{aws.String("CAPABILITY_IAM")},
		Parameters:   parameters,
		StackName:    aws.String(h.Resources.IngressStackPhysicalId),
		TemplateBody: aws.String(templateBody),
	}

	resp, err := h.Clients.Cloudformation.UpdateStack(updateStackInput)
	if err != nil {
		awsErr, ok := err.(awserr.RequestFailure)
		if ok && awsErr.Code() == "ValidationError" {
			if strings.Contains(awsErr.Message(), "No updates are to be performed.") {
				return nil
			}
			if strings.Contains(awsErr.Message(), "DELETE_COMPLETE") || strings.Contains(awsErr.Message(), "DELETE_IN_PROGESS") {
				go h.Stop()
				return nil
			}
		}
		return err
	}

	err = h.Clients.Cloudformation.WaitUntilStackUpdateComplete(&cloudformation.DescribeStacksInput{
		StackName: aws.String(stackName),
	})

	return err
}

// Generate json for current ingress template
func (h *Hacker) GenerateIngressTemplateJSON(sgs []*opsee_aws_ec2.SecurityGroup) ([]byte, error) {
	template := cf.NewTemplate()
	template.Description = "Listing of bastion security-group ingress rules."
	template.Parameters["BastionSecurityGroupId"] = &cf.Parameter{
		Description: "Bastion's security group id.",
		Type:        "String",
	}

	for _, sg := range sgs {
		// use the alphanumeric security group id  as physical id so we can get our current ingress rules with one api call
		sgid := strings.Replace(aws.StringValue(sg.GroupId), "sg-", "sg", 1)
		template.AddResource(fmt.Sprintf("%s", sgid), cf.EC2SecurityGroupIngress{
			IpProtocol:            cf.String("tcp"),
			FromPort:              cf.Integer(0),
			ToPort:                cf.Integer(65535),
			SourceSecurityGroupId: cf.Ref("BastionSecurityGroupId").String(),
			GroupId:               cf.String(*sg.GroupId),
		})
	}

	return json.Marshal(template)
}

// Fetch security groups from bezosphere
func (h *Hacker) DescribeSecurityGroups() ([]*opsee_aws_ec2.SecurityGroup, error) {
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
	resp, err := h.Clients.Bezos.Get(
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
			MaxAge: timestamp,
			Input:  &service.BezosRequest_Ec2_DescribeSecurityGroupsInput{input},
		})
	if err != nil {
		return nil, err
	}

	output := resp.GetEc2_DescribeSecurityGroupsOutput()
	if output == nil {
		return false, fmt.Errorf("error decoding aws response")
	}

	return output.SecurityGroups
}

type SecurityGroups []*opsee_aws_ec2.SecurityGroup

func (s SecurityGroups) Len() int      { return len(b) }
func (s SecurityGroups) Swap(i, j int) { b[i], b[j] = b[j], b[i] }

type ById struct{ SecurityGroups }

func (b ById) Less(i, j int) bool {
	return aws.StringValue(b[i].GroupID) < aws.StringValue(b[j].GroupID)
}

// Compare the current group ids to the new security groups.  Update if we have new or different group ids
func (h *Hacker) GroupsToUpdate(ogs []*opsee_aws_ec2.SecurityGroup, ngs []*opsee_aws_ec2.SecurityGroup) []*opsee_aws_ec2.SecurityGroup {
	var fgs []*opsee_aws_ec2.SecurityGroup

	// filter newGroups by key,value
	for i, sg := range ngs {
		skip := false
		for _, tag := range sg.Tags {
			k := aws.StringValue(tag.Key)
			v := aws.StringValue(tag.Value)

			if k == IgnoreIngressKey && v == IgnoreIngressValue {
				skip = true
			}
		}
		if !skip {
			fgs = append(fgs, sg)
		}
	}

	if len(fgs) != len(ogs) {
		return fgs
	}

	sort.Sort(ById{fgs})
	sort.Sort(ById{ogs}) // NOTE: these are just group ids! don't use them to update

	for i, _ := range fgs {
		if aws.StringValue(fgs[i].GroupId) != aws.StringValue(gs[i].GroupId) {
			return fgs
		}
	}

	return fgs
}

// Returns a semi-populated list of security groups retrieved from cloudformation resources
// NOTE we only use these to ensure that we don't update if there are no new groups!
func (h *Hacker) GetCurrentSecurityGroups() {
	resp, err := h.Clients.Cloudformation.DescribeStackResources(params)
	if err != nil {
		return err
	}

	var cgs []opsee_aws_ec2.SecurityGroup
	for _, resource := range resp.StackResources {
		lid := aws.StringValue(resource.LogicalResourceId)
		sgid := strings.Replace(aws.StringValue(sg.GroupId), "sg", "sg-", 1)
		if strings.HasPrefix(sgid, "sg-") {
			cgs := append(cgs, &opsee_aws_ec2.SecurityGroup{GroupId: sgid})
		}
	}
}

// Starts the hacker
func (h *Hacker) Start() {
	h.waitGroup.Add(1)
	defer h.waitGroup.Done()
	log.WithFields(h.Fields()).Info("Started hacker.")
	for {
		t := time.Now()
		for i := 0; i < 1; i++ {
			// get current security group ids
			csgs, err := h.GetCurrentSecurityGroups()
			if err != nil {
				log.WithFields(h.Fields()).Errorf("couldn't get current sgids from ingress stack: %s", err.Error())
				h.errCount += 1
				break
			}

			// get new security groups
			nsgs, err := h.DescribeSecurityGroups()
			if err != nil {
				log.WithFields(h.Fields()).Errorf("couldn't get new sgids: %s", err.Error())
				h.errCount += 1
				break
			}

			// diff the two
			usgs := h.GroupsToUpdate(csgs, nsgs)
			if len(usgs) > 0 {
				tl, err := h.GenerateIngressTemplateJSON(usgs)
				if err != nil {
					log.WithFields(h.Fields()).Errorf("couldn't generate ingress template json: %s", err.Error())
					h.errCount += 1
					break
				}

				err = h.UpdateIngressStack(string(tl))
				if err != nil {
					h.errCount += 1
					log.WithFields(h.Fields()).Errorf("couldn't update ingress stack: %s", err.Error())
					break
				} else {
					log.WithFields(h.Fields()).Info("updated ingress stack")
				}
			}
		}
		if errCount > ErrThreshold {
			return fmt.Errorf("reached error threshold... quitting")
		}
		if wait := HoldTime - time.Since(t); wait > time.Millisecond {
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

// Stop the hacker
func (h *Hacker) Stop() {
	close(h.kill)
	h.waitGroup.Wait()
	h.quit <- h.CustomerId
}
