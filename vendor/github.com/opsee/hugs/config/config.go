package config

import (
	"os"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/opsee/hugs/util"
	log "github.com/sirupsen/logrus"
)

// TODO(dan) consider splitting this into configs and testconfigs for each module
type Config struct {
	// PublicHost specifies the listen address for the API
	PublicHost string `required:"true"`
	// postgresConn is the Postgres connection string for the hugs database
	// e.g. postgres://user:pass@localhost/dbname
	PostgresConn string `required:"true"`
	// SqsUrl is the fully qualified HTTP endpoint for SQS where Hugs listens
	// for messages.
	SqsUrl string `required:"true"`
	// AWSRegion is the region of AWS where this instance of Hugs is operating.
	AWSRegion string `required:"true"`
	// OpseeHost is the public API endpoint for Opsee. This is used in notification
	// templates.
	OpseeHost string `required:"true"`
	// MandrillApiKey is the Mandrill API Key used for sending e-mail.
	MandrillApiKey string `required:"true"`
	// These two may not even be used.
	VapeEndpoint string `required:"true"`
	VapeKey      string `required:"true"`
	// LogLevel specifies the verbosity of hugs logging.
	LogLevel string
	// SlackClientSecret is the hugs Slack secret used during OAuth setup.
	SlackClientSecret string `required:"true"`
	// SlackClientID is used during OAuth setup.
	SlackClientID string `required:"true"`
	// SlackTestToken is used during Slack integration setup.
	SlackTestToken string
	// SlackTestClientSecret is used when running tests to test the slack
	// integration.
	SlackTestClientSecret string
	// SlackTestClientID is used when running tests to test the slack
	// integration.
	SlackTestClientID string
	// AWSSession is the shared `aws.Session` object used by all of the hugs components.
	AWSSession *session.Session
	// NotificaptionEndpoint is the URL of the notificaption service.
	NotificaptionEndpoint string
	// BartnetEndpoint is the URL of bartnet
	BartnetEndpoint string
	// YellerAPIKey is the API key used to report errors to the Yeller app
	YellerAPIKey string

	// global database connection
	DBConnection *sqlx.DB
}

func (this *Config) Validate() error {
	validator := &util.Validator{}
	if err := validator.Validate(this); err != nil {
		return err
	}
	return nil
}

var hugsConfig *Config
var once sync.Once

// initializes a database store to be used throughout the app
func (this *Config) getDatabaseConnection() {
	if this.DBConnection == nil {
		db, err := sqlx.Connect("postgres", this.PostgresConn)
		if err != nil {
			log.WithError(err).Fatal("Couldn't create database connection")
		}

		db.SetMaxOpenConns(10)
		db.SetMaxIdleConns(10)
		this.DBConnection = db
	}
}

func (this *Config) getAWSSession() {
	creds := credentials.NewChainCredentials(
		[]credentials.Provider{
			&ec2rolecreds.EC2RoleProvider{
				Client: ec2metadata.New(session.New()),
			},
			&credentials.EnvProvider{},
		})

	this.AWSSession = session.New(&aws.Config{
		Credentials: creds,
		MaxRetries:  aws.Int(3),
		Region:      aws.String(this.AWSRegion),
	})
}

func (this *Config) setLogLevel() {
	if len(this.LogLevel) > 0 {
		level, err := log.ParseLevel(this.LogLevel)
		if err == nil {
			log.SetLevel(level)
			return
		}
	}
	log.WithFields(log.Fields{"config": "setLogLevel"}).Warn("Could not set log level!")
}

func GetConfig() *Config {
	once.Do(func() {
		c := &Config{
			PublicHost:            os.Getenv("HUGS_HOST"),
			PostgresConn:          os.Getenv("HUGS_POSTGRES_CONN"),
			SqsUrl:                os.Getenv("HUGS_SQS_URL"),
			AWSRegion:             os.Getenv("HUGS_AWS_REGION"),
			OpseeHost:             os.Getenv("HUGS_OPSEE_HOST"),
			MandrillApiKey:        os.Getenv("HUGS_MANDRILL_API_KEY"),
			VapeEndpoint:          os.Getenv("HUGS_VAPE_ENDPOINT"),
			VapeKey:               os.Getenv("HUGS_VAPE_KEYFILE"),
			LogLevel:              os.Getenv("HUGS_LOG_LEVEL"),
			SlackClientID:         os.Getenv("HUGS_SLACK_CLIENT_ID"),
			SlackClientSecret:     os.Getenv("HUGS_SLACK_CLIENT_SECRET"),
			SlackTestToken:        os.Getenv("HUGS_TEST_SLACK_TOKEN"),
			SlackTestClientID:     os.Getenv("HUGS_TEST_SLACK_CLIENT_ID"),
			SlackTestClientSecret: os.Getenv("HUGS_TEST_SLACK_CLIENT_SECRET"),
			NotificaptionEndpoint: os.Getenv("HUGS_NOTIFICAPTION_ENDPOINT"),
			BartnetEndpoint:       os.Getenv("HUGS_BARTNET_ENDPOINT"),
			YellerAPIKey:          os.Getenv("HUGS_YELLER_API_KEY"),
		}
		if err := c.Validate(); err == nil {
			c.setLogLevel()
			c.getAWSSession()
			c.getDatabaseConnection()
			hugsConfig = c
		} else {
			log.WithFields(log.Fields{"config": "Validate", "error": err}).Fatal("Error generating config.")
		}
	})

	return hugsConfig
}
