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
						user_id			VARCHAR(36) NOT NULL,
						metadata		TEXT,
						UNIQUE (user_id),
						PRIMARY KEY (user_id)
					);
					INSERT INTO dashboards (user_id, metadata) VALUES ('admin', '');`,
				},
				Down: []string{
					`DROP TABLE IF EXISTS dashboards`,
				},
			},
		},
	}
}
