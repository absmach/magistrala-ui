// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"

	"github.com/absmach/magistrala-ui/ui"
	"github.com/jmoiron/sqlx"
)

type repo struct {
	db *sqlx.DB
}

func New(db *sqlx.DB) ui.DashboardRepository {
	return &repo{db: db}
}

// Create or update dashboard layout for a user.
func (r *repo) Save(ctx context.Context, dashboard ui.Dashboard) error {
	q := `
    INSERT INTO dashboards (user_id, metadata)
    VALUES (:user_id, :metadata)
    ON CONFLICT (user_id)
    DO UPDATE SET metadata = EXCLUDED.metadata`

	if _, err := r.db.NamedQueryContext(ctx, q, dashboard); err != nil {
		return HandleError(err, ErrCreateEntity)
	}
	return nil
}

// Get dashboard layout for a user.
func (r *repo) Get(ctx context.Context, id string) (ui.Dashboard, error) {
	q := `SELECT * FROM dashboards WHERE user_id = :user_id`
	var dashboard ui.Dashboard

	tmp := ui.Dashboard{
		UserID: id,
	}
	rows, err := r.db.NamedQueryContext(ctx, q, tmp)
	if err != nil {
		return ui.Dashboard{}, HandleError(err, ErrViewEntity)
	}
	defer rows.Close()

	if rows.Next() {
		if err = rows.StructScan(&dashboard); err != nil {
			return ui.Dashboard{}, HandleError(err, ErrViewEntity)
		}
		return dashboard, nil
	}

	return ui.Dashboard{}, ErrNotFound
}
