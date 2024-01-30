// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"context"
)

type Dashboard struct {
	UserID   string `json:"user_id,omitempty" db:"user_id"`
	Metadata string `json:"metadata,omitempty" db:"metadata"`
}

type DashboardRepository interface {
	// Persists dashboard layout for a user. A non-nil error is returned to indicate
	// a failure to persist.
	Save(ctx context.Context, dashboard Dashboard) error

	// Retrieves dashboard layout for a user. A non-nil error is returned to indicate
	// a failure to retrieve.
	Get(ctx context.Context, userID string) (Dashboard, error)
}
