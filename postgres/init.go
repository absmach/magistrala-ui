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
						dashboard_id VARCHAR(36) NOT NULL,
						created_by VARCHAR(36) NOT NULL,
						dashboard_name VARCHAR(255) NOT NULL,
						description TEXT,
						metadata TEXT,
						layout JSONB,
						created_at TIMESTAMP,
						updated_at TIMESTAMP,
						UNIQUE (dashboard_id),
						PRIMARY KEY (dashboard_id)
					);`,
				},
				Down: []string{
					`DROP TABLE IF EXISTS dashboards`,
				},
			},
		},
	}
}
