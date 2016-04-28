package svc

import (
	"crypto/tls"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/opsee/basic/schema"
	"github.com/opsee/basic/service"
	grpc_credentials "google.golang.org/grpc/credentials"
)

const SpanxProviderName = "SpanxProvider"
const ExpiryWindow = time.Duration(60 * time.Minute)
const Retries = 3

var (
	ErrSpanxCredentialsEmpty = awserr.New("EmptySpanxCreds", "spanx credentials are empty", nil)
)

type SpanxProvider struct {
	credentials.Value
	SpanxClient service.SpanxClient
	expiry      *credentials.Expiry
	User        *schema.User
}

func NewSpanxCredentials(user *schema.User) (*credentials.Credentials, error) {
	spanxProvider := &SpanxProvider{
		expiry: &credentials.Expiry{},
		User:   user,
	}

	val, err := spanxProvider.Retrieve()
	if err != nil {
		return nil, err
	}

	spanxProvider.Value = val
	return credentials.NewCredentials(spanxProvider), nil
}

func (s *SpanxProvider) GetSpanxCreds() (*credentials.Value, error) {
	conn, err := grpc.Dial("spanx.in.opsee.com:8443",
		grpc.WithTransportCredentials(grpc_credentials.NewTLS(&tls.Config{})),
		grpc.WithTimeout(tcpTimeout))
	if err != nil {
		log.WithError(err).Error("Couldn't connect to spanx.")
		return nil, ErrSpanxCredentialsEmpty
	}

	spanx := service.NewSpanxClient(conn)
	spanxResp, err := spanx.GetCredentials(context.Background(), &service.GetCredentialsRequest{
		User: s.User,
	})
	if err != nil {
		log.WithError(err).Error("Couldn't get spanx creds.")
		return nil, ErrSpanxCredentialsEmpty
	}
	credsVal := spanxResp.GetCredentials()
	awsCredsVal := &credentials.Value{
		AccessKeyID:     aws.StringValue(credsVal.AccessKeyID),
		SecretAccessKey: aws.StringValue(credsVal.SecretAccessKey),
		SessionToken:    aws.StringValue(credsVal.SessionToken),
	}

	return awsCredsVal, nil
}

func (s *SpanxProvider) UpdateExpiry() {
	s.expiry.SetExpiration(time.Now().UTC().Add(time.Duration(ExpiryWindow)), ExpiryWindow)
}

func (s *SpanxProvider) Retrieve() (credentials.Value, error) {
	var credsVal *credentials.Value
	for try := 0; try < Retries; try++ {
		value, err := s.GetSpanxCreds()
		if err != nil {
			log.WithError(err).Error("Couldn't get spanx creds")
			time.Sleep((1 << uint(try+1)) * time.Millisecond * 10)
			continue
		}
		if value != nil {
			credsVal = value
		}
		break
	}
	if credsVal == nil {
		return credentials.Value{}, ErrSpanxCredentialsEmpty
	}

	credsVal.ProviderName = SpanxProviderName
	s.UpdateExpiry()
	return *credsVal, nil
}

func (s *SpanxProvider) IsExpired() bool {
	return s.expiry.IsExpired()
}
