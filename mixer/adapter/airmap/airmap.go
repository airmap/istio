// Copyright 2018 AirMap Inc.

//go:generate $GOPATH/src/istio.io/istio/bin/mixer_codegen.sh -f mixer/adapter/airmap/config/config.proto

// Package airmap provides an adapter that dispatches to an in-cluster adapter via ReST.
// It implements the checkNothing, quota and listEntry templates.
package airmap

import (
	"context"
	"time"

	rpc "github.com/gogo/googleapis/google/rpc"

	"istio.io/istio/mixer/adapter/airmap/config"
	"istio.io/istio/mixer/pkg/adapter"
	"istio.io/istio/mixer/pkg/status"
	"istio.io/istio/mixer/template/apikey"
	"istio.io/istio/mixer/template/authorization"
	"istio.io/istio/mixer/template/quota"
)

type handler struct {
	result adapter.CheckResult
}

func defaultParam() *config.Params {
	return &config.Params{}
}

func newResult(*config.Params) adapter.CheckResult {
	return adapter.CheckResult{
		Status:        status.New(rpc.FAILED_PRECONDITION),
		ValidDuration: 5 * time.Second,
		ValidUseCount: 1000,
	}
}

////////////////// Runtime Methods //////////////////////////
func (h *handler) HandleApiKey(context.Context, *apikey.Instance) (adapter.CheckResult, error) {
	return h.result, nil
}

func (h *handler) HandleAuthorization(context.Context, *authorization.Instance) (adapter.CheckResult, error) {
	return h.result, nil
}

func (*handler) HandleQuota(context.Context, *quota.Instance, adapter.QuotaArgs) (adapter.QuotaResult, error) {
	return adapter.QuotaResult{}, nil
}

func (*handler) Close() error { return nil }

////////////////// Bootstrap //////////////////////////

// GetInfo returns the Info associated with this adapter implementation.
func GetInfo() adapter.Info {
	return adapter.Info{
		Name:        "airmap",
		Impl:        "istio.io/istio/mixer/adapter/airmap",
		Description: "Dispatches to an in-cluster adapter via ReST",
		SupportedTemplates: []string{
			apikey.TemplateName,
			authorization.TemplateName,
			quota.TemplateName,
		},
		DefaultConfig: defaultParam(),
		NewBuilder:    func() adapter.HandlerBuilder { return &builder{} },
	}
}

type builder struct {
	adapterConfig *config.Params
}

func (*builder) SetApiKeyTypes(map[string]*apikey.Type)               {}
func (*builder) SetAuthorizationTypes(map[string]*authorization.Type) {}
func (*builder) SetQuotaTypes(map[string]*quota.Type)                 {}
func (b *builder) SetAdapterConfig(cfg adapter.Config)                { b.adapterConfig = cfg.(*config.Params) }
func (*builder) Validate() (ce *adapter.ConfigErrors)                 { return }

func (b *builder) Build(context context.Context, env adapter.Env) (adapter.Handler, error) {
	return &handler{
		result: newResult(b.adapterConfig),
	}, nil
}
