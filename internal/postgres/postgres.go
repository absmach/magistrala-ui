// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"fmt"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/caarlos0/env/v10"
	_ "github.com/jackc/pgx/v5/stdlib" // required for SQL access
	"github.com/jmoiron/sqlx"
	migrate "github.com/rubenv/sql-migrate"
)

var (
	errConfig    = errors.New("failed to load postgresql configuration")
	errConnect   = errors.New("failed to connect to postgresql server")
	errMigration = errors.New("failed to apply migrations")
)

// Config defines the options that are used when connecting to the PostgresSQL instance.
type Config struct {
	Host        string `env:"MG_UI_DB_HOST"           envDefault:"localhost"`
	Port        string `env:"MG_UI_DB_PORT"           envDefault:"5430"`
	User        string `env:"MG_UI_DB_USER"           envDefault:"magistrala-ui"`
	Pass        string `env:"MG_UI_DB_PASS"           envDefault:"magistrala-ui"`
	Name        string `env:"MG_UI_DB_NAME"           envDefault:"dashboards"`
	SSLMode     string `env:"MG_UI_DB_SSL_MODE"       envDefault:"disable"`
	SSLCert     string `env:"MG_UI_DB_SSL_CERT"       envDefault:""`
	SSLKey      string `env:"MG_UI_DB_SSL_KEY"        envDefault:""`
	SSLRootCert string `env:"MG_UI_DB_SSL_ROOT_CERT"  envDefault:""`
}

// Setup creates a connection to the PostgreSQL instance and applies any
// unapplied database migrations. A non-nil error is returned to indicate failure.
func Setup(cfg Config, migrations migrate.MemoryMigrationSource) (*sqlx.DB, error) {
	if err := env.Parse(&cfg); err != nil {
		return nil, errors.Wrap(errConfig, err)
	}

	db, err := Connect(cfg)
	if err != nil {
		return nil, err
	}
	if err := MigrateDB(db, migrations); err != nil {
		return nil, err
	}
	return db, nil
}

// Connect creates a connection to the PostgreSQL instance.
func Connect(cfg Config) (*sqlx.DB, error) {
	url := fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=%s sslcert=%s sslkey=%s sslrootcert=%s", cfg.Host, cfg.Port, cfg.User, cfg.Name, cfg.Pass, cfg.SSLMode, cfg.SSLCert, cfg.SSLKey, cfg.SSLRootCert)

	db, err := sqlx.Open("pgx", url)
	if err != nil {
		return nil, errors.Wrap(errConnect, err)
	}

	return db, nil
}

// MigrateDB applies any unapplied database migrations.
func MigrateDB(db *sqlx.DB, migrations migrate.MemoryMigrationSource) error {
	if _, err := migrate.Exec(db.DB, "postgres", migrations, migrate.Up); err != nil {
		return errors.Wrap(errMigration, err)
	}

	return nil
}
