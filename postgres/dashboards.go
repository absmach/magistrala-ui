// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/absmach/magistrala-ui/ui"
	"github.com/absmach/magistrala/pkg/errors"
	"github.com/jmoiron/sqlx"
)

type repo struct {
	db *sqlx.DB
}

func New(db *sqlx.DB) ui.DashboardRepository {
	return &repo{db: db}
}

// Create a non-existing dashboard for a user.
func (r *repo) Create(ctx context.Context, dashboard ui.Dashboard) error {
	q := `
    INSERT INTO dashboards (dashboard_id, created_by, dashboard_name, description, metadata, layout, created_at, updated_at)
    VALUES (:dashboard_id, :created_by, :dashboard_name, :description, :metadata, :layout, :created_at, :updated_at)`

	dbDs, err := toDBDashboard(dashboard)
	if err != nil {
		return err
	}
	if _, err := r.db.NamedQueryContext(ctx, q, dbDs); err != nil {
		return HandleError(err, ErrCreateEntity)
	}
	return nil
}

// Retrieve a dashboard using a dashboard id and user id.
func (r *repo) Retrieve(ctx context.Context, dashboardID, userID string) (ui.Dashboard, error) {
	q := `SELECT dashboard_id, created_by,dashboard_name, description, metadata, layout, created_at, updated_at FROM dashboards WHERE dashboard_id = :dashboard_id AND created_by = :created_by`

	tmp := ui.Dashboard{
		DashboardID: dashboardID,
		CreatedBy:   userID,
	}
	rows, err := r.db.NamedQueryContext(ctx, q, tmp)
	if err != nil {
		return ui.Dashboard{}, HandleError(err, ErrViewEntity)
	}
	defer rows.Close()

	dbDs := dbDashboard{}
	if rows.Next() {
		if err = rows.StructScan(&dbDs); err != nil {
			return ui.Dashboard{}, HandleError(err, ErrViewEntity)
		}
		return toDashboard(dbDs)
	}

	return ui.Dashboard{}, ErrNotFound
}

// Retrieve all dashboards for a user using a user id.
func (r *repo) RetrieveAll(ctx context.Context, page ui.DashboardPageMeta) (ui.DashboardPage, error) {
	q := `SELECT dashboard_id, created_by, dashboard_name, description, metadata, created_at, updated_at FROM dashboards WHERE created_by = :created_by LIMIT :limit OFFSET :offset`

	rows, err := r.db.NamedQueryContext(ctx, q, page)
	if err != nil {
		return ui.DashboardPage{}, HandleError(err, ErrViewEntity)
	}
	defer rows.Close()

	var dashboards []ui.Dashboard
	for rows.Next() {
		dbDs := dbDashboard{}
		if err = rows.StructScan(&dbDs); err != nil {
			return ui.DashboardPage{}, HandleError(err, ErrViewEntity)
		}
		ds, err := toDashboard(dbDs)
		if err != nil {
			return ui.DashboardPage{}, HandleError(err, ErrViewEntity)
		}
		dashboards = append(dashboards, ds)
	}
	cq := `SELECT COUNT(*) FROM dashboards WHERE created_by = $1`
	var total uint64
	if err := r.db.GetContext(ctx, &total, cq, page.CreatedBy); err != nil {
		return ui.DashboardPage{}, HandleError(err, ErrViewEntity)
	}

	return ui.DashboardPage{
		Total:      total,
		Offset:     page.Offset,
		Limit:      page.Limit,
		Dashboards: dashboards,
	}, nil
}

// Update an existing dashboard for a user.
func (r *repo) Update(ctx context.Context, dashboardID, userID string, dr ui.DashboardReq) error {
	var query []string
	var upq string

	d := ui.Dashboard{
		DashboardID: dashboardID,
		CreatedBy:   userID,
	}
	if dr.DashboardName != "" {
		query = append(query, "dashboard_name = :dashboard_name")
		d.DashboardName = dr.DashboardName
	}
	if dr.Description != "" {
		query = append(query, "description = :description")
		d.Description = dr.Description
	}
	if dr.Metadata != "" {
		query = append(query, "metadata = :metadata")
		d.Metadata = dr.Metadata
	}
	if dr.Layout != "" {
		query = append(query, "layout = :layout")
		d.Layout = dr.Layout
	}
	if len(query) > 0 {
		upq = strings.Join(query, ",")
	}

	d.UpdatedAt = time.Now()

	q := fmt.Sprintf(`UPDATE dashboards SET %s, updated_at= :updated_at WHERE dashboard_id = :dashboard_id AND created_by = :created_by`, upq)

	dbDs, err := toDBDashboard(d)
	if err != nil {
		return err
	}
	res, err := r.db.NamedExecContext(ctx, q, dbDs)
	if err != nil {
		return HandleError(err, ErrCreateEntity)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete an existing dashboard for a user.
func (r *repo) Delete(ctx context.Context, dashboardID, userID string) error {
	q := `DELETE FROM dashboards WHERE dashboard_id = :dashboard_id AND created_by = :created_by`

	tmp := ui.Dashboard{
		DashboardID: dashboardID,
		CreatedBy:   userID,
	}
	res, err := r.db.NamedExecContext(ctx, q, tmp)
	if err != nil {
		return HandleError(err, ErrCreateEntity)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrNotFound
	}
	return nil
}

type dbDashboard struct {
	DashboardID   string    `db:"dashboard_id"`
	CreatedBy     string    `db:"created_by"`
	DashboardName string    `db:"dashboard_name"`
	Description   string    `db:"description"`
	Metadata      string    `db:"metadata"`
	Layout        []byte    `db:"layout"`
	CreatedAt     time.Time `db:"created_at"`
	UpdatedAt     time.Time `db:"updated_at"`
}

func toDBDashboard(ds ui.Dashboard) (dbDashboard, error) {
	lt, err := json.Marshal(ds.Layout)
	if err != nil {
		return dbDashboard{}, errors.Wrap(ErrJSONMarshal, err)
	}
	return dbDashboard{
		DashboardID:   ds.DashboardID,
		CreatedBy:     ds.CreatedBy,
		DashboardName: ds.DashboardName,
		Description:   ds.Description,
		Metadata:      ds.Metadata,
		Layout:        lt,
		CreatedAt:     ds.CreatedAt,
		UpdatedAt:     ds.UpdatedAt,
	}, nil
}

func toDashboard(dsDB dbDashboard) (ui.Dashboard, error) {
	var lt string
	if dsDB.Layout != nil {
		if err := json.Unmarshal(dsDB.Layout, &lt); err != nil {
			return ui.Dashboard{}, errors.Wrap(ErrJSONUnmarshal, err)
		}
	}

	return ui.Dashboard{
		DashboardID:   dsDB.DashboardID,
		CreatedBy:     dsDB.CreatedBy,
		DashboardName: dsDB.DashboardName,
		Description:   dsDB.Description,
		Metadata:      dsDB.Metadata,
		Layout:        lt,
		CreatedAt:     dsDB.CreatedAt,
		UpdatedAt:     dsDB.UpdatedAt,
	}, nil
}
