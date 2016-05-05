package svc

import (
	"crypto/tls"
	"os"
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

var (
	ErrSpanxCredentialsEmpty = awserr.New("EmptySpanxCreds", "spanx credentials are empty", nil)
)

type SpanxProvider struct {
	credentials.Expiry
	credentials.Value
	SpanxClient  service.SpanxClient
	User         *schema.User
	ExpiryWindow time.Duration
}

func NewSpanxCredentials(user *schema.User) (*credentials.Credentials, error) {
	spanxProvider := &SpanxProvider{
		User: user,
	}

	val, err := spanxProvider.Retrieve()
	if err != nil {
		return nil, err
	}

	spanxProvider.Value = val
	return credentials.NewCredentials(spanxProvider), nil
}

func (s *SpanxProvider) Retrieve() (credentials.Value, error) {
	awsCredsVal := credentials.Value{}
	conn, err := grpc.Dial(os.Getenv("HAILCANNON_SPANX_ADDRESS"),
		grpc.WithTransportCredentials(grpc_credentials.NewTLS(&tls.Config{})),
		grpc.WithTimeout(tcpTimeout))
	if err != nil {
		log.WithError(err).Error("Couldn't connect to spanx.")
		return awsCredsVal, ErrSpanxCredentialsEmpty
	}
	defer conn.Close()

	spanx := service.NewSpanxClient(conn)
	spanxResp, err := spanx.GetCredentials(context.Background(), &service.GetCredentialsRequest{
		User: s.User,
	})
	if err != nil {
		log.WithError(err).Error("Couldn't get spanx creds.")
		return awsCredsVal, ErrSpanxCredentialsEmpty
	}

	credsVal := spanxResp.GetCredentials()
	awsCredsVal = credentials.Value{
		AccessKeyID:     aws.StringValue(credsVal.AccessKeyID),
		SecretAccessKey: aws.StringValue(credsVal.SecretAccessKey),
		SessionToken:    aws.StringValue(credsVal.SessionToken),
	}
	credsVal.ProviderName = aws.String(SpanxProviderName)
	expiryTime, err := spanxResp.Expires.Value()
	if err == nil {
		s.SetExpiration(expiryTime.(time.Time), s.ExpiryWindow)
	} else {
		log.WithError(err).Warn("Retrieved credentials have no expiration time")
	}

	return awsCredsVal, nil
}

func (s *SpanxProvider) IsExpired() bool {
	return s.Expiry.IsExpired()
}
