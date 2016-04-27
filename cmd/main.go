package main

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/opsee/hugs/config"
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
	if h, ok := Hackers[key]; ok {
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
	hacker, err := NewHacker(cfg)
	if err != nil {
		log.WithError(err).Fatal("Error starting hacker.")
	}
	ah := &ActiveHackers{}

	// for each one create a new hacker.
	for {
		select {
		case s := <-signalsChannel:
			switch s {
			case syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT:
				log.Info("Received signal ", s, ". Stopping.")
				os.Exit(0)
			}
		case time.After(1 * time.Minute):
			// TODO(dan) get all active bastions
			activeBastions := getActiveBastions()
			for _, custyId := range activeBastions {
				if ah.Get(bastion) == nil {
					ah.Put(bastion, NewHacker(custyId, cfg))
				}
			}
		}
	}
}
