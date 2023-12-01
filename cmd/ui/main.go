// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/absmach/magistrala-ui/ui"
	"github.com/absmach/magistrala-ui/ui/api"
	"github.com/absmach/magistrala/logger"
	sdk "github.com/absmach/magistrala/pkg/sdk/go"
	"github.com/absmach/magistrala/pkg/uuid"
	"github.com/caarlos0/env/v9"
	"github.com/go-chi/chi/v5"
	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
)

type config struct {
	LogLevel        string          `env:"MG_UI_LOG_LEVEL"       envDefault:"info"`
	Port            string          `env:"MG_UI_PORT"            envDefault:"9095"`
	InstanceID      string          `env:"MG_UI_INSTANCE_ID"     envDefault:""`
	HTTPAdapterURL  string          `env:"MG_HTTP_ADAPTER_URL"   envDefault:"http://localhost:8008"`
	ReaderURL       string          `env:"MG_READER_URL"         envDefault:"http://localhost:9007"`
	ThingsURL       string          `env:"MG_THINGS_URL"         envDefault:"http://localhost:9000"`
	UsersURL        string          `env:"MG_USERS_URL"          envDefault:"http://localhost:9002"`
	HostURL         string          `env:"MG_UI_HOST_URL"        envDefault:"http://localhost:9095"`
	BootstrapURL    string          `env:"MG_BOOTSTRAP_URL"      envDefault:"http://localhost:9013"`
	DomainsURL      string          `env:"MG_DOMAINS_URL"        envDefault:"http://localhost:8189"`
	MsgContentType  sdk.ContentType `env:"MG_CONTENT-TYPE"       envDefault:"application/senml+json"`
	TLSVerification bool            `env:"MG_VERIFICATION_TLS"   envDefault:"false"`
}

func main() {
	cfg := config{}
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf(err.Error())
	}

	sdkConfig := sdk.Config{
		HTTPAdapterURL:  cfg.HTTPAdapterURL,
		ReaderURL:       cfg.ReaderURL,
		ThingsURL:       cfg.ThingsURL,
		UsersURL:        cfg.UsersURL,
		HostURL:         cfg.HostURL,
		MsgContentType:  cfg.MsgContentType,
		TLSVerification: cfg.TLSVerification,
		BootstrapURL:    cfg.BootstrapURL,
		DomainsURL:      cfg.DomainsURL,
	}

	logger, err := logger.New(os.Stdout, cfg.LogLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}

	if cfg.InstanceID == "" {
		if cfg.InstanceID, err = uuid.New().ID(); err != nil {
			log.Fatalf("Failed to generate instanceID: %s", err)
		}
	}

	sdk := sdk.NewSDK(sdkConfig)

	svc, err := ui.New(sdk)
	if err != nil {
		log.Fatalf(err.Error())
	}

	svc = api.LoggingMiddleware(svc, logger)
	svc = api.MetricsMiddleware(
		svc,
		kitprometheus.NewCounterFrom(stdprometheus.CounterOpts{
			Namespace: "ui",
			Subsystem: "api",
			Name:      "request_count",
			Help:      "Number of requests received.",
		}, []string{"method"}),
		kitprometheus.NewSummaryFrom(stdprometheus.SummaryOpts{
			Namespace: "ui",
			Subsystem: "api",
			Name:      "request_latency_microseconds",
			Help:      "Total duration of requests in microseconds.",
		}, []string{"method"}),
	)

	errs := make(chan error, 2)

	mux := chi.NewRouter()

	go func() {
		p := fmt.Sprintf(":%s", cfg.Port)
		logger.Info(fmt.Sprintf("GUI service started on port %s", cfg.Port))
		errs <- http.ListenAndServe(p, api.MakeHandler(svc, mux, cfg.InstanceID))
	}()

	go func() {
		c := make(chan os.Signal, 2)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	err = <-errs
	logger.Error(fmt.Sprintf("GUI service terminated: %s", err))
}
