// Copyright 2018 AirMap Inc.

//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -f mixer/adapter/airmap/config/config.proto

// Package airmap provides an adapter that dispatches to an in-cluster adapter via ReST.
// It implements the apikey and authorization templates.
package airmap

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"istio.io/istio/pkg/log"

	"google.golang.org/grpc/naming"

	"github.com/gogo/googleapis/google/rpc"
	"github.com/gogo/protobuf/types"
	"google.golang.org/grpc"
	"istio.io/istio/mixer/adapter/airmap/access"
	mq "istio.io/istio/mixer/adapter/airmap/amqpqueue"
	"istio.io/istio/mixer/adapter/airmap/config"
	"istio.io/istio/mixer/pkg/adapter"
	"istio.io/istio/mixer/template/authorization"
	"istio.io/istio/mixer/template/logentry"
)

const (
	keyAPIKey            = "api-key"
	keyVersion           = "version"
	defaultValidDuration = 5 * time.Second
)

var (
	statusCodeLut = map[access.Code]rpc.Code{
		access.CodeOK:            rpc.OK,
		access.CodeForbidden:     rpc.PERMISSION_DENIED,
		access.CodeUnauthorized:  rpc.UNAUTHENTICATED,
		access.CodeQuotaExceeded: rpc.RESOURCE_EXHAUSTED,
	}
)

type handler struct {
	controller access.ControllerClient
	amqpQueue  *mq.Queue
}

func defaultParam() *config.Params {
	return &config.Params{}
}

func (h *handler) HandleAuthorization(ctxt context.Context, instance *authorization.Instance) (adapter.CheckResult, error) {
	if u, err := url.Parse(instance.Action.Path); err == nil {
		// Handling the case of tiledata here: The api key comes in via a query parameter
		// named 'apikey' and envoy only extracts api keys from query parameters with keys:
		//   key
		//   api_key
		if s := u.Query().Get("apikey"); len(s) > 0 {
			instance.Subject.Properties[keyAPIKey] = s
		}

		instance.Action.Path = u.Path
	}

	params := access.AuthorizeAccessParameters{
		Subject: &access.AuthorizeAccessParameters_Subject{
			Credentials: &access.Credentials{
				Username: &access.Credentials_Username{
					AsString: instance.Subject.User,
				},
				Groups: []*access.Credentials_Group{
					&access.Credentials_Group{
						AsString: instance.Subject.Groups,
					},
				},
			},
		},
		Action: &access.AuthorizeAccessParameters_Action{
			Namespace: &access.API_Namespace{
				AsString: instance.Action.Namespace,
			},
			Name: &access.API_Name{
				AsString: instance.Action.Service,
			},
			Method: &access.API_Method{
				AsString: instance.Action.Method,
			},
		},
		Timestamp: types.TimestampNow(),
	}

	if auth, ok := instance.Subject.Properties["Authorization"].(string); ok {
		params.Raw = &access.Raw{
			Authorization: &access.Raw_Authorization{
				AsString: auth,
			},
		}
	}

	if v, present := instance.Subject.Properties[keyAPIKey]; present {
		if s, ok := v.(string); ok {
			params.Subject.Key = &access.API_Key{
				AsString: s,
			}
		}
	}

	if v, present := instance.Action.Properties[keyVersion]; present {
		if s, ok := v.(string); ok {
			params.Action.Version = &access.API_Version{
				AsString: s,
			}
		}
	}

	if len(instance.Action.Path) > 0 {
		params.Action.Resource = &access.API_Resource{
			AsString: instance.Action.Path,
		}
	}

	// 2 seconds is a random choice at this point in time. We obviously want to achieve way lower latency.
	// However, we need to make sure that we are not stalling incoming requests. In particular, as we are
	// potentially operating in the context of an ingress gateway.
	ctxt, cancel := context.WithTimeout(ctxt, 2*time.Second)
	defer cancel()

	result, err := h.controller.AuthorizeAccess(ctxt, &params)
	if err != nil {
		return adapter.CheckResult{
			Status: rpc.Status{
				Code: int32(rpc.INTERNAL),
			},
			ValidDuration: defaultValidDuration,
			ValidUseCount: 1,
		}, err
	}

	duration := defaultValidDuration

	if result.Validity != nil {
		duration, err = types.DurationFromProto(result.Validity.Duration)
		if err != nil {
			duration = defaultValidDuration
		}
	}

	return adapter.CheckResult{
		Status: rpc.Status{
			Code:    int32(statusCodeLut[result.Status.Code]),
			Message: result.Status.Message,
		},
		ValidDuration: duration,
		ValidUseCount: int32(result.Validity.Count),
	}, nil
}

func (h *handler) Close() error {
	if err := h.amqpQueue.Close(); err != nil {
		log.Error("failed to close amqp producer", zap.Error(err))
		return err
	}
	return nil
}

func (h *handler) HandleLogEntry(ctxt context.Context, instances []*logentry.Instance) error {
	h.amqpQueue.Push([]byte("Test on HandleLogEntry"))
	for _, instance := range instances {
		// TODO: Decide on formatting (perhaps just instance.Variables)
		entry, err := json.Marshal(instance)
		if err != nil {
			log.Error("failed to marshal log instance", zap.Error(err))
			continue
		}
		// TODO: UnsafePush vs Push, may want to escape here
		if err := h.amqpQueue.Push(entry); err != nil {
			log.Error("failed to push to amqp queue", zap.Error(err))
			continue
		}
	}

	return nil
}

// GetInfo returns the Info associated with this adapter implementation.
func GetInfo() adapter.Info {
	return adapter.Info{
		Name:        "airmap",
		Impl:        "istio.io/istio/mixer/adapter/airmap",
		Description: "Dispatches to an in-cluster adapter via ReST",
		SupportedTemplates: []string{
			authorization.TemplateName,
			logentry.TemplateName,
		},
		DefaultConfig: defaultParam(),
		NewBuilder: func() adapter.HandlerBuilder {
			balancer := grpc.Balancer(nil)
			resolver, err := naming.NewDNSResolver()
			if err != nil {
				log.Error("failed to instantiate naming resolver", zap.Error(err))
			} else {
				balancer = grpc.RoundRobin(resolver)
			}
			return &builder{
				balancer: balancer,
			}
		},
	}
}

var _ authorization.HandlerBuilder = &builder{}

var _ logentry.HandlerBuilder = &builder{}

type builder struct {
	adapterConfig *config.Params
	balancer      grpc.Balancer
	conn          *grpc.ClientConn
	guard         sync.Mutex
}

func (*builder) SetAuthorizationTypes(map[string]*authorization.Type) {}

// Set these later if we need to parse out types (marshalling directly right now)
func (b *builder) SetLogEntryTypes(map[string]*logentry.Type) {}

func (b *builder) SetAdapterConfig(cfg adapter.Config) {
	b.guard.Lock()
	defer b.guard.Unlock()

	if b.conn != nil {
		_ = b.conn.Close()
	}

	if b.adapterConfig = cfg.(*config.Params); b.adapterConfig != nil {
		options := []grpc.DialOption{
			grpc.WithInsecure(),
		}

		if b.balancer != nil {
			options = append(options, grpc.WithBalancer(b.balancer))
		}

		cc, err := grpc.Dial(b.adapterConfig.Endpoint, options...)
		if err != nil {
			b.conn = nil
		} else {
			b.conn = cc
		}
	}

}

func (*builder) Validate() (ce *adapter.ConfigErrors) {
	return
}

func (b *builder) Build(context context.Context, env adapter.Env) (adapter.Handler, error) {
	b.guard.Lock()
	defer b.guard.Unlock()

	if b.conn == nil {
		return nil, errors.New("invalid client connection")
	}

	amqpConnection := mq.New(b.adapterConfig.AmqpQueuename, joinStrings(
		"amqp://",
		b.adapterConfig.AmqpUsername,
		":",
		b.adapterConfig.AmqpPassword,
		"@",
		b.adapterConfig.AmqpHost,
		":",
		strconv.Itoa(int(b.adapterConfig.AmqpPort))))

	amqpConnection.Push([]byte("Test on Build"))

	return &handler{
		amqpQueue:  amqpConnection,
		controller: access.NewControllerClient(b.conn),
	}, nil
}

func joinStrings(stringSet ...string) string {
	var builtString strings.Builder
	for _, str := range stringSet {
		builtString.WriteString(str)
	}
	return builtString.String()
}
