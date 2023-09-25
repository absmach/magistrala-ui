// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/caarlos0/env/v9"
	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	"github.com/mainflux/mainflux/logger"
	sdk "github.com/mainflux/mainflux/pkg/sdk/go"
	"github.com/mainflux/mainflux/pkg/uuid"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	"github.com/ultravioletrs/mainflux-ui/ui"
	"github.com/ultravioletrs/mainflux-ui/ui/api"
)

type config struct {
	LogLevel        string          `env:"MF_UI_LOG_LEVEL"       envDefault:"info"`
	Port            string          `env:"MF_UI_PORT"            envDefault:"9090"`
	RedirectURL     string          `env:"MF_UI_REDIRECT_URL"    envDefault:"http://localhost:9090/"`
	InstanceID      string          `env:"MF_UI_INSTANCE_ID"     envDefault:""`
	HTTPAdapterURL  string          `env:"MF_HTTP_ADAPTER_URL"   envDefault:"http://localhost:8008"`
	ReaderURL       string          `env:"MF_READER_URL"         envDefault:""`
	ThingsURL       string          `env:"MF_THINGS_URL"         envDefault:"http://localhost:9000"`
	UsersURL        string          `env:"MF_USERS_URL"          envDefault:"http://localhost:9002"`
	HostURL         string          `env:"MF_UI_HOST_URL"        envDefault:"http://localhost:9090"`
	BootstrapURL    string          `env:"MF_BOOTSTRAP_URL"      envDefault:"http://localhost:9013"`
	MsgContentType  sdk.ContentType `env:"MF_CONTENT-TYPE"       envDefault:"application/senml+json"`
	TLSVerification bool            `env:"MF_VERIFICATION_TLS"   envDefault:"false"`
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

	svc := ui.New(sdk)

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

	go func() {
		p := fmt.Sprintf(":%s", cfg.Port)
		logger.Info(fmt.Sprintf("GUI service started on port %s", cfg.Port))
		errs <- http.ListenAndServe(p, api.MakeHandler(svc, cfg.RedirectURL, cfg.InstanceID))
	}()

	go func() {
		c := make(chan os.Signal, 2)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	err = <-errs
	logger.Error(fmt.Sprintf("GUI service terminated: %s", err))
}
