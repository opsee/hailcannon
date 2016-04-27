// The config package initializes global bastion configuration and provides a simple interface for interacting with
// that configuration data. It sets reasonable defaults that allow a build to pass.
package config

import (
	log "github.com/Sirupsen/logrus"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

var (
	config *Config = nil
)

func init() {
	viper.AutomaticEnv()
	viper.SetDefault("log_level", "info")

	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		config = NewConfig()
	})
}

// Global config provides shared aws session, metadata, and environmental variables declared in etc/opsee/bastion-env.sh.
type Config struct {
	LogLevel string
	AWS      *AWSConfig
}

func (this *Config) getAWSConfig() {
	awsConfig, err := NewAWSConfig()
	if err != nil {
		log.WithError(err).Fatal("Coudn't get AWS config.")
	} else {
		this.AWS = awsConfig
	}
}

func NewConfig() *Config {
	cfg := &Config{}

	level, err := log.ParseLevel(viper.GetString("log_level"))
	if err != nil {
		log.WithError(err).Warnf("Couldn't parse log level.")
	} else {
		log.SetLevel(level)
	}

	cfg.getAWSConfig()

	return cfg
}

// GetConfig returns a configuration object.
func GetConfig() *Config {
	if config == nil {
		config = NewConfig()
	}

	return config
}
