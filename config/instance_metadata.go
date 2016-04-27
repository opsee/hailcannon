package config

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
)

type InstanceMeta struct {
	Region string
	VpcId  string
}

func (this *InstanceMeta) Update() error {
	ec2MetadataClient := ec2metadata.New(session.New())
	region, err := ec2MetadataClient.Region()
	if err != nil {
		return err
	}

	mac, err := ec2MetadataClient.GetMetadata("network/interfaces/macs/")
	if err != nil {
		return err
	}

	vpcId, err := ec2MetadataClient.GetMetadata(fmt.Sprintf("network/interfaces/macs/%svpc-id", mac))
	if err != nil {
		return err
	}

	this.Region = region
	this.VpcId = vpcId

	return nil
}
