package main

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/opsee/hailcannon/config"
	"github.com/opsee/hailcannon/hacker"
)

const (
	moduleName = "hacker"
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

// TODO(dan) this actually will return an array of UUID
func getActiveBastions() []string {
	return []string{}
}

func main() {
	cfg := config.GetConfig()
	ah := &ActiveHackers{}

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
			activeBastions := getActiveBastions()
			for _, custyId := range activeBastions {
				if ah.Get(custyId) == nil {
					nh, err := hacker.NewHacker(custyId, cfg)
					if err != nil {
						log.WithError(err).Errorf("Couldn't create new hacker for customer %s", custyId)
					}
					ah.Put(custyId, nh)
				}
			}
		}
	}
}
