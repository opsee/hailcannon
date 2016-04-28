package main

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/opsee/basic/schema"
	"github.com/opsee/basic/service"
	"github.com/opsee/hailcannon/hacker"
	"github.com/opsee/hailcannon/svc"
)

const (
	moduleName = "hailcannon"
)

var (
	signalsChannel = make(chan os.Signal, 1)
)

func init() {
	signal.Notify(signalsChannel, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
}

type ActiveHackers struct {
	Hackers map[string]*hacker.Hacker
	sync.Mutex
}

func (ah *ActiveHackers) Get(key string) *hacker.Hacker {
	ah.Lock()
	defer ah.Unlock()
	if h, ok := ah.Hackers[key]; ok {
		return h
	}
	return nil
}

func (ah *ActiveHackers) Put(key string, h *hacker.Hacker) {
	ah.Lock()
	defer ah.Unlock()
	ah.Hackers[key] = h
}

func main() {
	ah := &ActiveHackers{}
	services := svc.NewOpseeServices()

	// for each one create a new hacker.
	for {
		select {
		case s := <-signalsChannel:
			switch s {
			case syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT:
				log.Infof("Received signal %s, Stopping.", s)
				os.Exit(0)
			}
		case <-time.After(1 * time.Minute):
			activeBastions, err := services.GetBastionStates([]string{}, &service.Filter{Key: "status", Value: "active"})
			if err != nil {
				log.WithError(err).Error("Couldn't get bastion states")
			}
			for _, bastion := range activeBastions {
				if ah.Get(bastion.CustomerId) == nil {
					creds, err := svc.NewSpanxCredentials(&schema.User{CustomerId: bastion.CustomerId})
					if err != nil {
						log.WithError(err).Errorf("Couldn't retrieve credentials for new hacker for customer %s", bastion.CustomerId)
						continue
					}
					nh, err := hacker.NewHacker(bastion, creds)
					if err != nil {
						log.WithError(err).Errorf("Couldn't create new hacker for customer %s", bastion.CustomerId)
						continue
					}
					log.Infof("Created hacker for customer %s", bastion.CustomerId)
					ah.Put(bastion.CustomerId, nh)
					// nh.HackForever()
				}
			}
		}
	}
}
