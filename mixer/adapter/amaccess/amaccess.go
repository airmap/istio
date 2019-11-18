// nolint:lll
// Generates the mygrpcadapter adapter's resource yaml. It contains the adapter's configuration, name,
// supported template names (metric in this case), and whether it is session or no-session based.
//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -a mixer/adapter/amaccess/config/config.proto -x "-s=false -n amaccess -t authorization -t logentry"

package amaccess

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"path"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	"istio.io/api/mixer/adapter/model/v1beta1"
	rpc "istio.io/gogo-genproto/googleapis/google/rpc"
	"istio.io/istio/mixer/adapter/amaccess/access"
	"istio.io/istio/mixer/template/authorization"
	"istio.io/istio/mixer/template/logentry"
	"istio.io/pkg/log"

	//"istio.io/istio/mixer/adapter/amaccess/config"
	"github.com/gogo/protobuf/types"
)

const (
	keyAuthorization = "authorization"
	keyAPIKey        = "api-key"
	keyVersion       = "version"
)

type (
	// Server is basic server interface
	Server interface {
		Addr() string
		Close() error
		Run(shutdown chan error)
	}

	// AmAccessGrpcAdapter supports authorization and logentry templates
	GrpcAdapter struct {
		listener   net.Listener
		server     *grpc.Server
		controller access.ControllerClient
		monitor    access.MonitorClient
	}
)

var (
	statusCodeLut = map[access.Code]rpc.Code{
		access.CodeOK:            rpc.OK,
		access.CodeForbidden:     rpc.PERMISSION_DENIED,
		access.CodeUnauthorized:  rpc.UNAUTHENTICATED,
		access.CodeQuotaExceeded: rpc.RESOURCE_EXHAUSTED,
	}

	errFailedClosingStream = errors.New("failed to close log access stream")
)

var _ authorization.HandleAuthorizationServiceServer = &GrpcAdapter{}
var _ logentry.HandleLogEntryServiceServer = &GrpcAdapter{}

//func (h *AmAccessGrpcAdapter) HandleAuthorization(ctxt context.Context, instance *authorization.Instance) (*v1beta1.CheckResult, error) {
func (h *GrpcAdapter) HandleAuthorization(ctxt context.Context, req *authorization.HandleAuthorizationRequest) (*v1beta1.CheckResult, error) {
	instance := req.Instance
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

	if auth, present := instance.Subject.Properties[keyAuthorization]; present {
		if s := auth.String(); s != "" {
			params.Raw = &access.Raw{
				Authorization: &access.Raw_Authorization{
					AsString: auth.String(),
				},
			}
		}
	}

	if v, present := instance.Subject.Properties[keyAPIKey]; present {
		if s := v.String(); s != "" {
			params.Subject.Key = &access.API_Key{
				AsString: s,
			}
		}
	}

	if u, err := url.Parse(instance.Action.Path); err == nil {
		// Handling the case of tiledata here: The api key comes in via a query parameter
		// named 'apikey' and envoy only extracts api keys from query parameters with keys:
		//   key
		//   api_key
		if s := u.Query().Get("apikey"); len(s) > 0 {
			params.Subject.Key = &access.API_Key{
				AsString: s,
			}
		}
	}

	if v, present := instance.Action.Properties[keyVersion]; present {
		if s := v.String(); s != "" {
			params.Action.Version = &access.API_Version{
				AsString: s,
			}
		}
	}

	if len(instance.Action.Path) > 0 {
		params.Action.Resource = &access.API_Resource{
			AsString: path.Clean(instance.Action.Path),
		}
	}

	// 2 seconds is a random choice at this point in time. We obviously want to achieve way lower latency.
	// However, we need to make sure that we are not stalling incoming requests. In particular, as we are
	// potentially operating in the context of an ingress gateway.
	ctxt, cancel := context.WithTimeout(ctxt, 2*time.Second)
	defer cancel()

	result, err := h.controller.AuthorizeAccess(ctxt, &params)
	if err != nil {
		return &v1beta1.CheckResult{
			Status: rpc.Status{
				Code:    int32(statusCodeLut[result.Status.Code]),
				Message: result.Status.Message,
			},
		}, err
	}
	var (
		duration = defaultValidDuration
		count    = defaultValidCount
	)

	if result.Validity != nil {
		duration, err = types.DurationFromProto(result.Validity.Duration)
		if err != nil {
			duration = defaultValidDuration
		}

		if count = int32(result.Validity.Count); count < 0 {
			count = 0
		}
	}

	return &v1beta1.CheckResult{
		Status: rpc.Status{
			Code:    int32(statusCodeLut[result.Status.Code]),
			Message: result.Status.Message,
		},
		ValidDuration: duration,
		ValidUseCount: count,
	}, nil
}

func (h *GrpcAdapter) HandleLogEntry(ctxt context.Context, req *logentry.HandleLogEntryRequest) (*v1beta1.ReportResult, error) {
	instances := req.Instances
	stream, err := h.monitor.MonitorAccess(ctxt)
	if err != nil {
		return nil, err
	}

	for _, instance := range instances {
		ts := instance.Timestamp.GetValue()

		l := access.Log{
			Request: &access.Log_Request{
				Id: defaultValues.requestID.id,
				Subject: &access.Log_Request_Subject{
					Ip:        defaultValues.subject.ip,
					Key:       defaultValues.subject.key,
					UserAgent: defaultValues.subject.userAgent,
				},
				Action: &access.Log_Request_Action{
					Namespace: defaultValues.action.namespace,
					Name:      defaultValues.action.name,
					Version:   defaultValues.action.version,
					Method:    defaultValues.action.method,
					Resource:  defaultValues.action.resource,
				},
			},
			Response: &access.Log_Response{
				Code:    defaultValues.response.code,
				Message: defaultValues.response.message,
			},
			Timestamp: ts,
		}

		if v, ok := instance.Variables["requestId"]; ok {
			if id := v; id != nil {
				l.Request.Id.AsString = id.String()
			}
		}

		if v, ok := instance.Variables["xForwardedFor"]; ok {
			if ip := v; ip != nil {
				l.Request.Subject.Ip = &access.Source_IP{
					AsBytes: net.ParseIP(ip.String()),
				}
			}
		} else {
			if v, ok := instance.Variables["sourceIp"]; ok {
				if ip := v.GetIpAddressValue(); ip != nil {
					l.Request.Subject.Ip = &access.Source_IP{
						AsBytes: ip.Value,
					}
				} else {
					log.Errorf("failed to type cast IP address: %T", v)
				}
			} else {
				log.Error("missing variable in logentry", zap.String("key", "sourceIp"))
			}
		}

		if v := instance.Variables["apiKey"]; v != nil {
			l.Request.Subject.Key = &access.API_Key{
				AsString: v.String(),
			}
		}

		if v := instance.Variables["authorization"]; v != nil {
			l.Request.Subject.Authorization = &access.Raw_Authorization{
				AsString: v.String(),
			}
		}

		if v := instance.Variables["userAgent"]; v != nil {
			l.Request.Subject.UserAgent = &access.Source_UserAgent{
				AsString: v.String(),
			}
		}

		if v := instance.Variables["destinationName"]; v != nil {
			l.Request.Action.Name = &access.API_Name{
				AsString: v.String(),
			}
		}

		if v := instance.Variables["destinationNamespace"]; v != nil {
			l.Request.Action.Namespace = &access.API_Namespace{
				AsString: v.String(),
			}
		}

		if v := instance.Variables["method"]; v != nil {
			l.Request.Action.Method = &access.API_Method{
				AsString: v.String(),
			}
		}

		if v := instance.Variables["url"]; v != nil {
			l.Request.Action.Resource = &access.API_Resource{
				AsString: v.String(),
			}
		}

		if v := instance.Variables["responseCode"]; v != nil {
			l.Response.Code = &access.Log_Response_Code{
				AsInt64: v.GetInt64Value(),
			}
		}

		// The response message is left empty for now as we are focusing on
		// calls to our ReST APIs.

		// We deliver the individual entry via our stream, logging but otherwise
		// ignoring the error. The error handling policy focuses on being as
		// robust and fault-tolerant as possible.
		if err := stream.Send(&l); err != nil {
			log.Error("failed to stream log entry", zap.Error(err))
		}
	}

	_, err = stream.CloseAndRecv()
	switch err {
	case nil:
		return nil, errFailedClosingStream
	case io.EOF:
		return &v1beta1.ReportResult{}, nil
	default:
		return nil, err
	}

}

// Addr returns the listening address of the server
func (h *GrpcAdapter) Addr() string {
	return h.listener.Addr().String()
}

// Run starts the server run
func (h *GrpcAdapter) Run(shutdown chan error) {
	shutdown <- h.server.Serve(h.listener)
}

// Close gracefully shuts down the server; used for testing
func (h *GrpcAdapter) Close() error {
	if h.server != nil {
		h.server.GracefulStop()
	}

	if h.listener != nil {
		_ = h.listener.Close()
	}

	return nil
}

// NewAmAccessAdapter creates a new amaccess adapter that listens at provided port.
func NewAmAccessAdapter(addr string) (Server, error) {
	if addr == "" {
		addr = "0"
	}
	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", addr))
	if err != nil {
		return nil, fmt.Errorf("unable to listen on socket: %v", err)
	}
	s := &GrpcAdapter{
		listener: listener,
	}
	fmt.Printf("listening on \"%v\"\n", s.Addr())
	s.server = grpc.NewServer()
	authorization.RegisterHandleAuthorizationServiceServer(s.server, s)
	logentry.RegisterHandleLogEntryServiceServer(s.server, s)

	return s, nil
}
