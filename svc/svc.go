package svc

import (
	"crypto/tls"
	"log"
	"time"

	"github.com/opsee/basic/schema"
	opsee_aws_credentials "github.com/opsee/basic/schema/aws/credentials"
	"github.com/opsee/basic/service"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	grpc_credentials "google.golang.org/grpc/credentials"
)

const tcpTimeout = time.Duration(3) * time.Second

type OpseeServices struct {
	vape     service.VapeClient
	spanx    service.SpanxClient
	keelhaul service.KeelhaulClient
	//	awsSession session.Session
}

func NewOpseeServices() *OpseeServices {
	services := &OpseeServices{}
	services.initSpanx()
	services.initKeelhaul()
	services.initVape()
	return services
}

func (o *OpseeServices) initVape() {
	if o.vape != nil {
		return
	}
	conn, err := grpc.Dial("vape.in.opsee.com:443",
		grpc.WithTransportCredentials(grpc_credentials.NewTLS(&tls.Config{})),
		grpc.WithTimeout(tcpTimeout),
		grpc.WithBlock())
	if err != nil {
		log.Fatal(err)
	}
	o.vape = service.NewVapeClient(conn)
}

func (o *OpseeServices) initSpanx() {
	if o.spanx != nil {
		return
	}
	conn, err := grpc.Dial("spanx.in.opsee.com:8443",
		grpc.WithTransportCredentials(grpc_credentials.NewTLS(&tls.Config{})),
		grpc.WithTimeout(tcpTimeout))
	if err != nil {
		panic(err)
	}
	o.spanx = service.NewSpanxClient(conn)
}

func (o *OpseeServices) initKeelhaul() {
	if o.keelhaul != nil {
		return
	}
	conn, err := grpc.Dial("keelhaul.in.opsee.com:443",
		grpc.WithTransportCredentials(grpc_credentials.NewTLS(&tls.Config{})),
		grpc.WithTimeout(tcpTimeout))
	if err != nil {
		panic(err)
	}
	o.keelhaul = service.NewKeelhaulClient(conn)
}

func (o *OpseeServices) GetRoleCreds(user *schema.User) (*opsee_aws_credentials.Value, error) {
	o.initSpanx()

	spanxResp, err := o.spanx.GetCredentials(context.Background(), &service.GetCredentialsRequest{
		User: user,
	})
	if err != nil {
		return nil, err
	}

	return spanxResp.GetCredentials(), nil
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

func (o *OpseeServices) GetUser(email string, custID string) (*schema.User, error) {
	o.initVape()

	userResp, err := o.vape.GetUser(context.Background(), &service.GetUserRequest{
		Email:      email,
		CustomerId: custID,
	})
	if err != nil {
		return nil, err
	}

	return userResp.User, nil
}
