// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package postgres_test

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	pg "github.com/absmach/magistrala-ui/internal/postgres"
	dpostgres "github.com/absmach/magistrala-ui/postgres"
	"github.com/jmoiron/sqlx"
	dockertest "github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

var db *sqlx.DB

func TestMain(m *testing.M) {
	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}

	container, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "postgres",
		Tag:        "16.1-alpine",
		Env: []string{
			"POSTGRES_USER=magistrala-ui",
			"POSTGRES_PASSWORD=magistrala-ui",
			"POSTGRES_DB=dashboards",
			"POSTGRES_HOST_AUTH_METHOD=trust",
			"POSTGRES_PORT=5432:5432",
			"listen_addresses = '*'",
		},
	}, func(config *docker.HostConfig) {
		config.AutoRemove = true
		config.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		log.Fatalf("Could not start container: %s", err)
	}

	port := container.GetPort("5432/tcp")

	pool.MaxWait = 120 * time.Second
	if err := pool.Retry(func() error {
		url := fmt.Sprintf("host=localhost port=%s user=magistrala-ui dbname=dashboards password=magistrala-ui sslmode=disable", port)
		db, err := sql.Open("pgx", url)
		if err != nil {
			return err
		}
		return db.Ping()
	}); err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}

	dbConfig := pg.Config{
		Port: port,
	}
	prefix := "MG_UI_DB_"
	if db, err = pg.SetupWithConfig(prefix, *dpostgres.Migration(), dbConfig); err != nil {
		log.Fatalf("Could not setup test DB connection: %s", err)
	}

	code := m.Run()

	db.Close()
	if err := pool.Purge(container); err != nil {
		log.Fatalf("Could not purge container: %s", err)
	}

	os.Exit(code)
}
