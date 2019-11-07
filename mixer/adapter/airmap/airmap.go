// Copyright 2018 AirMap Inc.

//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -f mixer/adapter/airmap/config/config.proto

// Package airmap provides an adapter that dispatches to an in-cluster adapter via ReST.
// It implements the checkNothing, quota and listEntry templates.
package airmap

import (
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"path"
	"time"

	"istio.io/istio/mixer/pkg/status"

	"go.uber.org/zap"
	"istio.io/pkg/log"

	// "github.com/gogo/googleapis/google/rpc"
	rpc "istio.io/gogo-genproto/googleapis/google/rpc"
	"github.com/gogo/protobuf/types"
	"istio.io/istio/mixer/adapter/airmap/access"
	"istio.io/istio/mixer/adapter/airmap/config"
	"istio.io/istio/mixer/pkg/adapter"
	"istio.io/istio/mixer/template/authorization"
	"istio.io/istio/mixer/template/logentry"
)

const (
	keyAuthorization = "authorization"
	keyAPIKey        = "api-key"
	keyVersion       = "version"
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

type handler struct {
	controller access.ControllerClient
	monitor    access.MonitorClient
}

func defaultParam() *config.Params {
	return &config.Params{}
}

func (h *handler) HandleAuthorization(ctxt context.Context, instance *authorization.Instance) (adapter.CheckResult, error) {
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

	if auth, ok := instance.Subject.Properties[keyAuthorization].(string); ok {
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
		if s, ok := v.(string); ok {
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
		return adapter.CheckResult{
			Status: status.WithPermissionDenied(err.Error()),
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

	return adapter.CheckResult{
		Status: rpc.Status{
			Code:    int32(statusCodeLut[result.Status.Code]),
			Message: result.Status.Message,
		},
		ValidDuration: duration,
		ValidUseCount: count,
	}, nil
}

func (h *handler) HandleLogEntry(ctxt context.Context, instances []*logentry.Instance) error {
	stream, err := h.monitor.MonitorAccess(ctxt)
	if err != nil {
		return err
	}

	for _, instance := range instances {
		ts, err := types.TimestampProto(instance.Timestamp)
		if err != nil {
			ts = types.TimestampNow()
		}

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
			if id, ok := v.(string); ok {
				l.Request.Id.AsString = id
			}
		}

		if v, ok := instance.Variables["xForwardedFor"]; ok {
			if ip, ok := v.(string); ok {
				l.Request.Subject.Ip = &access.Source_IP{
					AsBytes: net.ParseIP(ip),
				}
			}
		} else {
			if v, ok := instance.Variables["sourceIp"]; ok {
				if ip, ok := v.(net.IP); ok {
					l.Request.Subject.Ip = &access.Source_IP{
						AsBytes: ip,
					}
				} else {
					log.Errorf("failed to type cast IP address: %T", v)
				}
			} else {
				log.Error("missing variable in logentry", zap.String("key", "sourceIp"))
			}
		}

		if v, ok := instance.Variables["apiKey"].(string); ok {
			l.Request.Subject.Key = &access.API_Key{
				AsString: v,
			}
		}

		if v, ok := instance.Variables["authorization"].(string); ok {
			l.Request.Subject.Authorization = &access.Raw_Authorization{
				AsString: v,
			}
		}

		if v, ok := instance.Variables["userAgent"].(string); ok {
			l.Request.Subject.UserAgent = &access.Source_UserAgent{
				AsString: v,
			}
		}

		if v, ok := instance.Variables["destinationName"].(string); ok {
			l.Request.Action.Name = &access.API_Name{
				AsString: v,
			}
		}

		if v, ok := instance.Variables["destinationNamespace"].(string); ok {
			l.Request.Action.Namespace = &access.API_Namespace{
				AsString: v,
			}
		}

		if v, ok := instance.Variables["method"].(string); ok {
			l.Request.Action.Method = &access.API_Method{
				AsString: v,
			}
		}

		if v, ok := instance.Variables["url"].(string); ok {
			l.Request.Action.Resource = &access.API_Resource{
				AsString: v,
			}
		}

		if v, ok := instance.Variables["responseCode"].(int64); ok {
			l.Response.Code = &access.Log_Response_Code{
				AsInt64: v,
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
		return errFailedClosingStream
	case io.EOF:
		return nil
	default:
		return err
	}

}

func (h *handler) Close() error {
	return nil
}
