package svc

import (
	"crypto/tls"
	"os"
	"time"

	"github.com/opsee/basic/schema"
	"github.com/opsee/basic/service"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	grpc_credentials "google.golang.org/grpc/credentials"
)

const tcpTimeout = time.Duration(15) * time.Second

type OpseeServices struct {
	keelhaul service.KeelhaulClient
}

func NewOpseeServices() *OpseeServices {
	services := &OpseeServices{}
	services.initKeelhaul()
	return services
}

func (o *OpseeServices) initKeelhaul() {
	if o.keelhaul != nil {
		return
	}
	conn, err := grpc.Dial(os.Getenv("HAILCANNON_KEELHAUL_ADDRESS"),
		grpc.WithTransportCredentials(grpc_credentials.NewTLS(&tls.Config{})),
		grpc.WithTimeout(tcpTimeout))
	if err != nil {
		panic(err)
	}
	o.keelhaul = service.NewKeelhaulClient(conn)
}

func (o *OpseeServices) GetBastionStates(customerIDs []string, filters ...*service.Filter) ([]*schema.BastionState, error) {
	o.initKeelhaul()

	keelResp, err := o.keelhaul.ListBastionStates(context.Background(), &service.ListBastionStatesRequest{
		CustomerIds: customerIDs,
		Filters:     filters,
	})
	if err != nil {
		return nil, err
	}

	return keelResp.GetBastionStates(), nil
}
