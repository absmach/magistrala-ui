// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	_ "github.com/jackc/pgx/v5/stdlib"
	migrate "github.com/rubenv/sql-migrate"
)

// Migration of dashboards table.
func Migration() *migrate.MemoryMigrationSource {
	return &migrate.MemoryMigrationSource{
		Migrations: []*migrate.Migration{
			{
				Id: "dashboard_01",
				Up: []string{
					`CREATE TABLE IF NOT EXISTS dashboards (
						id VARCHAR(36) NOT NULL,
						created_by VARCHAR(36) NOT NULL,
						name VARCHAR(255) NOT NULL,
						description TEXT,
						layout JSONB,
						created_at TIMESTAMP,
						updated_at TIMESTAMP,
						UNIQUE (id),
						PRIMARY KEY (id)
					);`,
				},
				Down: []string{
					`DROP TABLE IF EXISTS dashboards`,
				},
			},
		},
	}
}
