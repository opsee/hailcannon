package spanxcreds

import (
	"crypto/tls"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/opsee/basic/schema"
	"github.com/opsee/basic/service"
	log "github.com/sirupsen/logrus"
	grpc_credentials "google.golang.org/grpc/credentials"
)

const SpanxProviderName = "SpanxProvider"

var (
	ErrSpanxCredentialsEmpty            = awserr.New("EmptySpanxCreds", "spanx credentials are empty", nil)
	ErrSpanxConnectionFailed            = awserr.New("SpanxConnectionFailed", "failed to connect to spanx", nil)
	ErrSpanxGetCredentialsRequestFailed = awserr.New("SpanxGetCredentialsRequestFailed", "failed to get credentials from spanx", nil)
)

type SpanxProvider struct {
	credentials.Expiry
	credentials.Value
	user *schema.User

	// equired spanxclient for connecting to spanx service
	Client service.SpanxClient

	// ExpiryWindow will allow the credentials to trigger refreshing prior to
	// the credentials actually expiring. This is beneficial so race conditions
	// with expiring credentials do not cause request to fail unexpectedly
	// due to ExpiredTokenException exceptions.
	//
	// So a ExpiryWindow of 10s would cause calls to IsExpired() to return true
	// 10 seconds before the credentials are actually expired.
	//
	// If ExpiryWindow is 0 or less it will be ignored.
	ExpiryWindow time.Duration
	retrieved    bool
}

func NewSpanxCredentials(spanxUser *schema.User) *credentials.Credentials {
	return credentials.NewCredentials(&SpanxProvider{
		user: spanxUser,
	})
}

// Retrieve credentials from spanx via GPRC
func (s *SpanxProvider) Retrieve() (credentials.Value, error) {
	s.retrieved = false
	conn, err := grpc.Dial("spanx.in.opsee.com:8443",
		grpc.WithTransportCredentials(grpc_credentials.NewTLS(&tls.Config{})),
		grpc.WithTimeout(time.Second*15))
	if err != nil {
		log.WithError(err).Error("Couldn't connect to spanx.")
		return credentials.Value{ProviderName: SpanxProviderName}, ErrSpanxConnectionFailed
	}
	spanx := service.NewSpanxClient(conn)
	defer conn.Close()

	spanxResp, err := spanx.GetCredentials(context.Background(), &service.GetCredentialsRequest{
		User: s.user,
	})
	if err != nil {
		log.WithError(err).Error("Couldn't get spanx creds.")
		return credentials.Value{ProviderName: SpanxProviderName}, ErrSpanxGetCredentialsRequestFailed
	}

	credsVal := spanxResp.GetCredentials()
	awsCredsVal := credentials.Value{
		AccessKeyID:     aws.StringValue(credsVal.AccessKeyID),
		SecretAccessKey: aws.StringValue(credsVal.SecretAccessKey),
		SessionToken:    aws.StringValue(credsVal.SessionToken),
		ProviderName:    SpanxProviderName,
	}

	expiryTime, err := spanxResp.Expires.Value()
	if err == nil {
		s.SetExpiration(expiryTime.(time.Time), s.ExpiryWindow)
		s.retrieved = true
	}

	return awsCredsVal, nil
}

func (s *SpanxProvider) IsExpired() bool {
	if s.retrieved == false {
		return false
	}
	return s.Expiry.IsExpired()
}
