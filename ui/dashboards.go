// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"context"
)

type Dashboard struct {
	DashboardID string `json:"dashboard_id,omitempty" db:"dashboard_id"`
	UserID      string `json:"user_id,omitempty" db:"user_id"`
	Description string `json:"description,omitempty" db:"description"`
	Metadata    string `json:"metadata,omitempty" db:"metadata"`
	Layout      string `json:"layout,omitempty" db:"layout"`
}

type DashboardPage struct {
	Total      uint64      `json:"total"`
	Offset     uint64      `json:"offset"`
	Limit      uint64      `json:"limit"`
	Dashboards []Dashboard `json:"dashboards"`
}

type DashboardPageMeta struct {
	Total  uint64 `json:"total"`
	Offset uint64 `json:"offset"`
	Limit  uint64 `json:"limit"`
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
	RetrieveAll(ctx context.Context, userID string, page DashboardPageMeta) (DashboardPage, error)

	// Updates a dashboard for a user. A non-nil error is returned to indicate
	// a failure to update.
	Update(ctx context.Context, dashboard Dashboard) error

	// Deletes a dashboard for a user. A non-nil error is returned to indicate
	// a failure to delete.
	Delete(ctx context.Context, dashboardID, userID string) error
}
