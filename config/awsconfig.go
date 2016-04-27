package config

import (
	"os"

	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/private/endpoints"
)

type AWSConfig struct {
	metaData *InstanceMeta
	session  *session.Session
}

func NewAWSConfig() (*AWSConfig, error) {
	awsConfig := &AWSConfig{}

	sess, err := awsConfig.Session()
	if err != nil {
		return nil, err
	}

	awsConfig.session = sess
	log.Info("got session")

	return awsConfig, nil
}

// returns existing metadata
func (this *AWSConfig) MetaData() (*InstanceMeta, error) {
	if this.metaData != nil {
		return this.metaData, nil
	}

	metaData := &InstanceMeta{
		Region: os.Getenv("AWS_DEFAULT_REGION"),
		VpcId:  "",
	}
	err := metaData.Update()
	if err != nil {
		log.WithError(err).Warn("Couldn't get metadata from metadata service. Region set to AWS_DEFAULT_REGION")
	}

	return metaData, nil
}

func (this *AWSConfig) Session() (*session.Session, error) {
	if this.session != nil {
		return this.session, nil
	}

	metaData, err := this.MetaData()
	if err != nil {
		return nil, err
	}

	creds := credentials.NewChainCredentials(
		[]credentials.Provider{
			&ec2rolecreds.EC2RoleProvider{
				Client: ec2metadata.New(session.New()),
			},
			&credentials.EnvProvider{},
		})

	sess := session.New(&aws.Config{
		Credentials: creds,
		Region:      aws.String(metaData.Region),
	})

	return sess, nil
}

func (this *AWSConfig) ClientConfig(serviceName string, cfgs ...*aws.Config) client.Config {
	s, err := this.Session()
	if err != nil {
		log.WithError(err).Fatal("Couldn't get session from global config.")
	}

	s = s.Copy(cfgs...)
	endpoint, signingRegion := endpoints.NormalizeEndpoint(
		aws.StringValue(s.Config.Endpoint), serviceName,
		aws.StringValue(s.Config.Region), aws.BoolValue(s.Config.DisableSSL))

	return client.Config{
		Config:        s.Config,
		Handlers:      s.Handlers,
		Endpoint:      endpoint,
		SigningRegion: signingRegion,
	}
}
