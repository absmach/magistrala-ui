// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
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
						id VARCHAR(36) NOT NULL CHECK (id <> ''),
						created_by VARCHAR(36) NOT NULL CHECK (created_by <> ''),
						name VARCHAR(255) NOT NULL CHECK (name <> ''),
						description TEXT,
						layout JSONB,
						metadata JSONB,
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
