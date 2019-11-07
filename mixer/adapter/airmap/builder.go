package airmap

import (
	"context"
	"errors"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/naming"
	"istio.io/istio/mixer/adapter/airmap/access"
	"istio.io/istio/mixer/adapter/airmap/config"
	"istio.io/istio/mixer/pkg/adapter"
	"istio.io/istio/mixer/template/authorization"
	"istio.io/istio/mixer/template/logentry"
	"istio.io/pkg/log"
)

// GetInfo returns the Info associated with this adapter implementation.
func GetInfo() adapter.Info {
	return adapter.Info{
		Name:        "airmap",
		Impl:        "istio.io/istio/mixer/adapter/airmap",
		Description: "Dispatches to an in-cluster adapter via gRPC",
		SupportedTemplates: []string{
			authorization.TemplateName,
			logentry.TemplateName,
		},
		DefaultConfig: defaultParam(),
		NewBuilder: func() adapter.HandlerBuilder {
			b := &builder{}

			resolver, err := naming.NewDNSResolverWithFreq(30 * time.Second)
			if err != nil {
				log.Error("failed to instantiate naming resolver", zap.Error(err))
			} else {
				b.controller.balancer = grpc.RoundRobin(resolver)
				b.monitor.balancer = grpc.RoundRobin(resolver)
			}

			return b
		},
	}
}

var _ authorization.HandlerBuilder = &builder{}
var _ logentry.HandlerBuilder = &builder{}

type builder struct {
	guard         sync.Mutex
	adapterConfig *config.Params
	controller    struct {
		balancer grpc.Balancer
		conn     *grpc.ClientConn
	}
	monitor struct {
		balancer grpc.Balancer
		conn     *grpc.ClientConn
	}
}

func (*builder) SetAuthorizationTypes(map[string]*authorization.Type) {}
func (*builder) SetLogEntryTypes(map[string]*logentry.Type)           {}

func (b *builder) SetAdapterConfig(cfg adapter.Config) {
	b.guard.Lock()
	defer b.guard.Unlock()

	if b.controller.conn != nil {
		_ = b.controller.conn.Close()
	}

	if b.monitor.conn != nil {
		_ = b.monitor.conn.Close()
	}

	if b.adapterConfig = cfg.(*config.Params); b.adapterConfig != nil {
		controllerOptions := []grpc.DialOption{
			grpc.WithInsecure(),
			grpc.WithBlock(),
		}

		if b.controller.balancer != nil {
			controllerOptions = append(controllerOptions, grpc.WithBalancer(b.controller.balancer))
		}

		cc, err := grpc.Dial(b.adapterConfig.Controller, controllerOptions...)
		if err != nil {
			b.controller.conn = nil
		} else {
			b.controller.conn = cc
		}

		monitorOptions := []grpc.DialOption{
			grpc.WithInsecure(),
			grpc.WithBlock(),
		}

		if b.monitor.balancer != nil {
			monitorOptions = append(monitorOptions, grpc.WithBalancer(b.monitor.balancer))
		}

		cc, err = grpc.Dial(b.adapterConfig.Monitor, monitorOptions...)
		if err != nil {
			b.monitor.conn = nil
		} else {
			b.monitor.conn = cc
		}
	}
}

func (*builder) Validate() (ce *adapter.ConfigErrors) {
	return
}

func (b *builder) Build(context context.Context, env adapter.Env) (adapter.Handler, error) {
	b.guard.Lock()
	defer b.guard.Unlock()

	if b.controller.conn == nil || b.monitor.conn == nil {
		return nil, errors.New("invalid client connection")
	}

	return &handler{
		controller: access.NewControllerClient(b.controller.conn),
		monitor:    access.NewMonitorClient(b.monitor.conn),
	}, nil
}
