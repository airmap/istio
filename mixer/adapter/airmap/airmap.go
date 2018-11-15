// Copyright 2018 AirMap Inc.

//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -f mixer/adapter/airmap/config/config.proto
//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -f mixer/adapter/airmap/access/access.proto

// Package airmap provides an adapter that dispatches to an in-cluster adapter via ReST.
// It implements the apikey and authorization templates.
package airmap

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"time"

	"go.uber.org/zap"
	"istio.io/istio/pkg/log"

	"google.golang.org/grpc/naming"

	"github.com/gogo/googleapis/google/rpc"
	"github.com/gogo/protobuf/types"
	"google.golang.org/grpc"
	"istio.io/istio/mixer/adapter/airmap/access"
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
	controller    access.ControllerClient
	logEntryTypes map[string]*logentry.Type
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
	return nil
}

func (h *handler) HandleLogEntry(ctxt context.Context, instances []*logentry.Instance) error {

	for _, ins := range instances {

		instanceTimestamp, err := types.TimestampProto(ins.Timestamp)
		if err != nil {
			return err
		}

		// Need to define our own template, as this is very fragile.  First run only.
		params := access.InsertAccessLogParameters{
			Severity:              ins.Severity,
			Timestamp:             instanceTimestamp,
			MonitoredResourceType: ins.MonitoredResourceType,
			Variables: &access.AccessLogEntry_Variables{
				Source: &access.AccessLogEntry_Source{
					Ip:        ins.Variables["sourceIp"].([]byte),
					App:       ins.Variables["sourceApp"].(string),
					Principal: ins.Variables["sourcePrincipal"].(string),
					Name:      ins.Variables["sourceName"].(string),
					Workload:  ins.Variables["sourceWorkload"].(string),
					Namespace: ins.Variables["sourceNamespace"].(string),
					Owner:     ins.Variables["sourceOwner"].(string),
				},
				Destination: &access.AccessLogEntry_Destination{
					App:         ins.Variables["destinationApp"].(string),
					Ip:          ins.Variables["destinationIp"].([]byte),
					Servicehost: ins.Variables["destinationServiceHost"].(string),
					Workload:    ins.Variables["destinationWorkload"].(string),
					Name:        ins.Variables["destinationName"].(string),
					Namespace:   ins.Variables["destinationNamespace"].(string),
					Owner:       ins.Variables["destinationOwner"].(string),
					Principal:   ins.Variables["destinationPrincipal"].(string),
				},
				Request: &access.AccessLogEntry_Request{
					ApiClaims:     ins.Variables["apiClaims"].(string),
					ApiKey:        ins.Variables["apiKey"].(string),
					Protocol:      ins.Variables["protocol"].(string),
					Method:        ins.Variables["method"].(string),
					Url:           ins.Variables["url"].(string),
					UrlPath:       ins.Variables["urlPath"].(string),
					RequestSize:   ins.Variables["requestSize"].(int64),
					RequestId:     ins.Variables["requestId"].(int64),
					ClientTraceId: ins.Variables["clientTraceId"].(string),
					UserAgent:     ins.Variables["userAgent"].(string),
					ReceivedBytes: ins.Variables["receivedBytes"].(int64),
					Referer:       ins.Variables["referer"].(string),
					HttpAuthority: ins.Variables["httpAuthority"].(string),
					XForwardedFor: ins.Variables["xForwardedFor"].(string),
				},
				Response: &access.AccessLogEntry_Response{
					ResponseCode:      ins.Variables["responseCode"].(int64),
					ResponseSize:      ins.Variables["responseSize"].(int64),
					Latency:           ins.Variables["latency"].(*types.Duration),
					ResponseTimestamp: ins.Variables["responseTimestamp"].(*types.Timestamp),
					SentBytes:         ins.Variables["sentBytes"].(int64),
					GrpcStatus:        ins.Variables["grpcStatus"].(string),
					GrpcMessage:       ins.Variables["grpcMessage"].(string),
				},
				Internal: &access.AccessLogEntry_Internal{
					ConnectionSecurityPolicy: ins.Variables["connection_security_policy"].(string),
					RequestedServerName:      ins.Variables["requestedServerName"].(string),
					Reporter:                 ins.Variables["reporter"].(string),
				},
			},
		}

		ctxt, cancel := context.WithTimeout(ctxt, 2*time.Second)
		defer cancel()

		if _, err := h.controller.InsertAccessLog(ctxt, &params); err != nil {
			return err
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
	logEntryTypes map[string]*logentry.Type
}

func (*builder) SetAuthorizationTypes(map[string]*authorization.Type) {}

func (b *builder) SetLogEntryTypes(importTypes map[string]*logentry.Type) {
	b.logEntryTypes = importTypes
}

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

	return &handler{
		controller:    access.NewControllerClient(b.conn),
		logEntryTypes: b.logEntryTypes,
	}, nil
}
