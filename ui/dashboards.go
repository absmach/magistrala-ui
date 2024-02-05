// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"context"
	"time"
)

type Dashboard struct {
	DashboardID   string    `json:"dashboard_id,omitempty" db:"dashboard_id"`
	CreatedBy     string    `json:"created_by,omitempty" db:"created_by"`
	DashboardName string    `json:"dashboard_name,omitempty" db:"dashboard_name"`
	Description   string    `json:"description,omitempty" db:"description"`
	Metadata      string    `json:"metadata,omitempty" db:"metadata"`
	Layout        string    `json:"layout,omitempty" db:"layout"`
	CreatedAt     time.Time `json:"created_at,omitempty" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at,omitempty" db:"updated_at"`
}

type DashboardPage struct {
	Total      uint64      `json:"total"`
	Offset     uint64      `json:"offset"`
	Limit      uint64      `json:"limit"`
	Dashboards []Dashboard `json:"dashboards"`
}

type DashboardPageMeta struct {
	Total     uint64 `json:"total" db:"total"`
	Offset    uint64 `json:"offset" db:"offset"`
	Limit     uint64 `json:"limit" db:"limit"`
	CreatedBy string `json:"created_by" db:"created_by"`
}

type DashboardReq struct {
	DashboardName string `json:"dashboard_name,omitempty"`
	Description   string `json:"description,omitempty"`
	Metadata      string `json:"metadata,omitempty"`
	Layout        string `json:"layout,omitempty"`
}

type DashboardRepository interface {
	// Persists dashboard  for a user. A non-nil error is returned to indicate
	// a failure to persist.
	Create(ctx context.Context, dashboard Dashboard) error

	// Retrieves dashboard for a user. A non-nil error is returned to indicate
	// a failure to retrieve.
	Retrieve(ctx context.Context, dashboardID, userID string) (Dashboard, error)

	// Retrieves all dashboards for a user. A non-nil error is returned to indicate
	// a failure to retrieve all.
	RetrieveAll(ctx context.Context, page DashboardPageMeta) (DashboardPage, error)

	// Updates a dashboard for a user. A non-nil error is returned to indicate
	// a failure to update.
	Update(ctx context.Context, dashboardID string, userID string, dr DashboardReq) error

	// Deletes a dashboard for a user. A non-nil error is returned to indicate
	// a failure to delete.
	Delete(ctx context.Context, dashboardID, userID string) error
}
