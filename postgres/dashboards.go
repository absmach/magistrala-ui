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
func (r *repo) Create(ctx context.Context, dashboard ui.Dashboard) (ui.Dashboard, error) {
	q := `
    INSERT INTO dashboards (id, created_by, name, description, layout, metadata, created_at, updated_at)
    VALUES (:id, :created_by, :name, :description, :layout, :metadata, :created_at, :updated_at)
	RETURNING id, created_by, name, description, layout, created_at`

	dbDs, err := toDBDashboard(dashboard)
	if err != nil {
		return ui.Dashboard{}, HandleError(err, ErrCreateEntity)
	}
	row, err := r.db.NamedQueryContext(ctx, q, dbDs)
	if err != nil {
		return ui.Dashboard{}, HandleError(err, ErrCreateEntity)
	}
	defer row.Close()
	row.Next()
	dbDs = dbDashboard{}
	if err = row.StructScan(&dbDs); err != nil {
		return ui.Dashboard{}, HandleError(err, ErrCreateEntity)
	}
	ds, err := toDashboard(dbDs)
	if err != nil {
		return ui.Dashboard{}, HandleError(err, ErrCreateEntity)
	}

	return ds, nil
}

// Retrieve a dashboard using a dashboard id and user id.
func (r *repo) Retrieve(ctx context.Context, dashboardID, userID string) (ui.Dashboard, error) {
	q := `SELECT id, created_by, name, description, layout, metadata, created_at, updated_at
	FROM dashboards WHERE id = :id AND created_by = :created_by`

	tmp := ui.Dashboard{
		ID:        dashboardID,
		CreatedBy: userID,
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
	q := `SELECT id, created_by, name, description, created_at, updated_at FROM dashboards
	WHERE created_by = :created_by
	ORDER BY created_at DESC
	LIMIT :limit
	OFFSET :offset`

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
		ID:        dashboardID,
		CreatedBy: userID,
	}
	if dr.Name != "" {
		query = append(query, "name = :name")
		d.Name = dr.Name
	}
	if dr.Description != "" {
		query = append(query, "description = :description")
		d.Description = dr.Description
	}
	if dr.Layout != "" {
		query = append(query, "layout = :layout")
		d.Layout = dr.Layout
	}
	if dr.Metadata != "" {
		query = append(query, "metadata = :metadata")
		d.Metadata = dr.Metadata
	}
	if len(query) > 0 {
		upq = strings.Join(query, ",")
	}

	d.UpdatedAt = time.Now()

	q := fmt.Sprintf(`UPDATE dashboards SET %s, updated_at= :updated_at WHERE id = :id AND created_by = :created_by`, upq)

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
	q := `DELETE FROM dashboards WHERE id = :id AND created_by = :created_by`

	tmp := ui.Dashboard{
		ID:        dashboardID,
		CreatedBy: userID,
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
	ID          string    `db:"id"`
	CreatedBy   string    `db:"created_by"`
	Name        string    `db:"name"`
	Description string    `db:"description"`
	Layout      []byte    `db:"layout"`
	Metadata    []byte    `db:"metadata"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
}

func toDBDashboard(ds ui.Dashboard) (dbDashboard, error) {
	lt, err := json.Marshal(ds.Layout)
	if err != nil {
		return dbDashboard{}, errors.Wrap(ErrJSONMarshal, err)
	}
	ma, err := json.Marshal(ds.Metadata)
	if err != nil {
		return dbDashboard{}, errors.Wrap(ErrJSONMarshal, err)
	}
	return dbDashboard{
		ID:          ds.ID,
		CreatedBy:   ds.CreatedBy,
		Name:        ds.Name,
		Description: ds.Description,
		Layout:      lt,
		Metadata:    ma,
		CreatedAt:   ds.CreatedAt,
		UpdatedAt:   ds.UpdatedAt,
	}, nil
}

func toDashboard(dsDB dbDashboard) (ui.Dashboard, error) {
	var lt string
	if dsDB.Layout != nil {
		if err := json.Unmarshal(dsDB.Layout, &lt); err != nil {
			return ui.Dashboard{}, errors.Wrap(ErrJSONUnmarshal, err)
		}
	}
	var ma string
	if dsDB.Metadata != nil {
		if err := json.Unmarshal(dsDB.Metadata, &ma); err != nil {
			return ui.Dashboard{}, errors.Wrap(ErrJSONUnmarshal, err)
		}
	}

	return ui.Dashboard{
		ID:          dsDB.ID,
		CreatedBy:   dsDB.CreatedBy,
		Name:        dsDB.Name,
		Description: dsDB.Description,
		Layout:      lt,
		Metadata:    ma,
		CreatedAt:   dsDB.CreatedAt,
		UpdatedAt:   dsDB.UpdatedAt,
	}, nil
}
