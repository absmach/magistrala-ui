// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/absmach/magistrala-ui/internal/postgres"
	repo "github.com/absmach/magistrala-ui/postgres"
	"github.com/absmach/magistrala-ui/ui"
	"github.com/absmach/magistrala-ui/ui/api"
	sdk "github.com/absmach/magistrala/pkg/sdk/go"
	"github.com/absmach/magistrala/pkg/uuid"
	"github.com/caarlos0/env/v10"
	"github.com/go-chi/chi/v5"
	kitprometheus "github.com/go-kit/kit/metrics/prometheus"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
)

type config struct {
	LogLevel           string          `env:"MG_UI_LOG_LEVEL"         envDefault:"debug"`
	Port               string          `env:"MG_UI_PORT"              envDefault:"9095"`
	InstanceID         string          `env:"MG_UI_INSTANCE_ID"       envDefault:""`
	HTTPAdapterURL     string          `env:"MG_HTTP_ADAPTER_URL"     envDefault:"http://localhost:8008"`
	ReaderURL          string          `env:"MG_READER_URL"           envDefault:"http://localhost:9007"`
	ThingsURL          string          `env:"MG_THINGS_URL"           envDefault:"http://localhost:9000"`
	UsersURL           string          `env:"MG_USERS_URL"            envDefault:"http://localhost:9002"`
	HostURL            string          `env:"MG_UI_HOST_URL"          envDefault:"http://localhost:9095"`
	BootstrapURL       string          `env:"MG_BOOTSTRAP_URL"        envDefault:"http://localhost:9013"`
	DomainsURL         string          `env:"MG_DOMAINS_URL"          envDefault:"http://localhost:8189"`
	InvitationsURL     string          `env:"MG_INVITATIONS_URL"      envDefault:"http://localhost:9020"`
	MsgContentType     sdk.ContentType `env:"MG_UI_CONTENT_TYPE"      envDefault:"application/senml+json"`
	TLSVerification    bool            `env:"MG_UI_VERIFICATION_TLS"  envDefault:"false"`
	KratosURL          string          `env:"MG_KRATOS_URL"           envDefault:"http://localhost:4433"`
	KratosClientID     string          `env:"MG_KRATOS_CLIENT_ID"     envDefault:""`
	KratosClientSecret string          `env:"MG_KRATOS_CLIENT_SECRET" envDefault:""`
	KratosRedirectURL  string          `env:"MG_KRATOS_REDIRECT_URL"  envDefault:"http://localhost/oauth/callback/kratos"`
	KratosState        string          `env:"MG_KRATOS_STATE"         envDefault:""`
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
		InvitationsURL:  cfg.InvitationsURL,
	}

	logger, err := initLogger(cfg.LogLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}

	if cfg.InstanceID == "" {
		if cfg.InstanceID, err = uuid.New().ID(); err != nil {
			log.Fatalf("Failed to generate instanceID: %s", err)
		}
	}

	sdk := sdk.NewSDK(sdkConfig)
	kconf := ui.NewKratosConfig(cfg.KratosURL, cfg.KratosClientID, cfg.KratosClientSecret, cfg.KratosState, cfg.KratosRedirectURL)

	dbConfig := postgres.Config{}
	db, err := postgres.Setup(dbConfig, *repo.Migration())
	if err != nil {
		log.Fatalf("Failed to setup postgres db : %s", err)
	}

	dbs := repo.New(db)

	idp := uuid.New()

	svc, err := ui.New(sdk, dbs, idp, &kconf)
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
		logger.Info("GUI service started", slog.String("port", p))
		errs <- http.ListenAndServe(p, api.MakeHandler(svc, mux, cfg.InstanceID))
	}()

	go func() {
		c := make(chan os.Signal, 2)
		signal.Notify(c, syscall.SIGINT)
		errs <- fmt.Errorf("%s", <-c)
	}()

	err = <-errs
	logger.Error("GUI service terminated", slog.String("err", err.Error()))
}

func initLogger(levelText string) (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(levelText)); err != nil {
		return &slog.Logger{}, fmt.Errorf(`{"level":"error","message":"%s: %s","ts":"%s"}`, err, levelText, time.RFC3339Nano)
	}

	logHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})

	return slog.New(logHandler), nil
}
