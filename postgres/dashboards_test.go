// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package postgres_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/0x6flab/namegenerator"
	"github.com/absmach/magistrala-ui/postgres"
	"github.com/absmach/magistrala-ui/ui"
	"github.com/absmach/magistrala/pkg/errors"
	"github.com/absmach/magistrala/pkg/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var namegen = namegenerator.NewGenerator()

func TestCreate(t *testing.T) {
	t.Cleanup(func() {
		_, err := db.Exec("DELETE FROM dashboards")
		require.Nil(t, err, fmt.Sprintf("clean dashboards unexpected error: %s", err))
	})

	id := generateUUID(t)

	cases := []struct {
		desc      string
		dashboard ui.Dashboard
		err       error
	}{
		{
			desc: "create new dashboard",
			dashboard: ui.Dashboard{
				ID:          id,
				CreatedBy:   generateUUID(t),
				Name:        namegen.Generate(),
				Description: namegen.Generate(),
				Layout:      namegen.Generate(),
				Metadata:    namegen.Generate(),
				CreatedAt:   time.Now().UTC().Truncate(time.Millisecond),
			},
			err: nil,
		},
		{
			desc: "create existing dashboard",
			dashboard: ui.Dashboard{
				ID:          id,
				CreatedBy:   generateUUID(t),
				Name:        namegen.Generate(),
				Description: namegen.Generate(),
				Layout:      namegen.Generate(),
				Metadata:    namegen.Generate(),
				CreatedAt:   time.Now().UTC().Truncate(time.Millisecond),
			},
			err: postgres.ErrConflict,
		},
		{
			desc: "create new dashboard with empty id",
			dashboard: ui.Dashboard{
				ID:          "",
				CreatedBy:   generateUUID(t),
				Name:        namegen.Generate(),
				Description: namegen.Generate(),
				Layout:      namegen.Generate(),
				Metadata:    namegen.Generate(),
				CreatedAt:   time.Now().UTC().Truncate(time.Millisecond),
			},
			err: postgres.ErrCreateEntity,
		},
		{
			desc: "create new dashboard with empty created by",
			dashboard: ui.Dashboard{
				ID:          generateUUID(t),
				CreatedBy:   "",
				Name:        namegen.Generate(),
				Description: namegen.Generate(),
				Layout:      namegen.Generate(),
				Metadata:    namegen.Generate(),
				CreatedAt:   time.Now().UTC().Truncate(time.Millisecond),
			},
			err: postgres.ErrCreateEntity,
		},
		{
			desc: "create new dashboard with empty name",
			dashboard: ui.Dashboard{
				ID:          generateUUID(t),
				CreatedBy:   generateUUID(t),
				Name:        "",
				Description: namegen.Generate(),
				Layout:      namegen.Generate(),
				Metadata:    namegen.Generate(),
				CreatedAt:   time.Now().UTC().Truncate(time.Millisecond),
			},
			err: postgres.ErrCreateEntity,
		},
		{
			desc: "create new dashboard with empty description",
			dashboard: ui.Dashboard{
				ID:          generateUUID(t),
				CreatedBy:   generateUUID(t),
				Name:        namegen.Generate(),
				Description: "",
				Layout:      namegen.Generate(),
				Metadata:    namegen.Generate(),
				CreatedAt:   time.Now().UTC().Truncate(time.Millisecond),
			},
			err: nil,
		},
		{
			desc: "create new dashboard with empty layout",
			dashboard: ui.Dashboard{
				ID:          generateUUID(t),
				CreatedBy:   generateUUID(t),
				Name:        namegen.Generate(),
				Description: namegen.Generate(),
				Layout:      "",
				Metadata:    namegen.Generate(),
				CreatedAt:   time.Now().UTC().Truncate(time.Millisecond),
			},
			err: nil,
		},
		{
			desc: "create new dashboard with empty metadata",
			dashboard: ui.Dashboard{
				ID:          generateUUID(t),
				CreatedBy:   generateUUID(t),
				Name:        namegen.Generate(),
				Description: namegen.Generate(),
				Layout:      namegen.Generate(),
				Metadata:    "",
				CreatedAt:   time.Now().UTC().Truncate(time.Millisecond),
			},
			err: nil,
		},
		{
			desc: "create new dashboard with malformed id",
			dashboard: ui.Dashboard{
				ID:          strings.Repeat("a", 37),
				CreatedBy:   generateUUID(t),
				Name:        namegen.Generate(),
				Description: namegen.Generate(),
				Layout:      namegen.Generate(),
				Metadata:    namegen.Generate(),
				CreatedAt:   time.Now().UTC().Truncate(time.Millisecond),
			},
			err: postgres.ErrMalformedEntity,
		},
		{
			desc: "create new dashboard with malformed created by",
			dashboard: ui.Dashboard{
				ID:          generateUUID(t),
				CreatedBy:   strings.Repeat("a", 37),
				Name:        namegen.Generate(),
				Description: namegen.Generate(),
				Layout:      namegen.Generate(),
				Metadata:    namegen.Generate(),
				CreatedAt:   time.Now().UTC().Truncate(time.Millisecond),
			},
			err: postgres.ErrMalformedEntity,
		},
		{
			desc: "create new dashboard with malformed name",
			dashboard: ui.Dashboard{
				ID:          generateUUID(t),
				CreatedBy:   generateUUID(t),
				Name:        strings.Repeat("a", 256),
				Description: namegen.Generate(),
				Layout:      namegen.Generate(),
				Metadata:    namegen.Generate(),
				CreatedAt:   time.Now().UTC().Truncate(time.Millisecond),
			},
			err: postgres.ErrMalformedEntity,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			rDashboard, err := repo.Create(context.Background(), tc.dashboard)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s to contain: %s", err, tc.err))
			if err == nil {
				tc.dashboard.Metadata = ""
				assert.Equal(t, tc.dashboard, rDashboard)
			}
		})
	}
}

func TestRetrieve(t *testing.T) {
	t.Cleanup(func() {
		_, err := db.Exec("DELETE FROM dashboards")
		require.Nil(t, err, fmt.Sprintf("clean dashboards unexpected error: %s", err))
	})

	dashboard := ui.Dashboard{
		ID:          generateUUID(t),
		CreatedBy:   generateUUID(t),
		Name:        namegen.Generate(),
		Description: namegen.Generate(),
		Layout:      namegen.Generate(),
		Metadata:    namegen.Generate(),
		CreatedAt:   time.Now().UTC().Truncate(time.Millisecond),
	}
	_, err := repo.Create(context.Background(), dashboard)
	require.Nil(t, err, fmt.Sprintf("create dashboard unexpected error: %s", err))

	cases := []struct {
		desc        string
		dashboardID string
		userID      string
		err         error
	}{
		{
			desc:        "retrieve existing dashboard",
			dashboardID: dashboard.ID,
			userID:      dashboard.CreatedBy,
			err:         nil,
		},
		{
			desc:        "retrieve non-existing dashboard",
			dashboardID: generateUUID(t),
			userID:      generateUUID(t),
			err:         postgres.ErrNotFound,
		},
		{
			desc:        "retrieve existing dashboard with malformed id",
			dashboardID: strings.Repeat("a", 37),
			userID:      dashboard.CreatedBy,
			err:         postgres.ErrNotFound,
		},
		{
			desc:        "retrieve existing dashboard with malformed created by",
			dashboardID: dashboard.ID,
			userID:      strings.Repeat("a", 37),
			err:         postgres.ErrNotFound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			dashboard, err := repo.Retrieve(context.Background(), tc.dashboardID, tc.userID)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s to contain: %s", err, tc.err))
			if err == nil {
				assert.Equal(t, dashboard.ID, tc.dashboardID)
				assert.Equal(t, dashboard.CreatedBy, tc.userID)
			}
		})
	}
}

func TestRetrieveAll(t *testing.T) {
	t.Cleanup(func() {
		_, err := db.Exec("DELETE FROM dashboards")
		require.Nil(t, err, fmt.Sprintf("clean dashboards unexpected error: %s", err))
	})

	createdBy := generateUUID(t)
	num := 200
	var items []ui.Dashboard
	now := time.Now().UTC().Truncate(time.Millisecond)
	for i := 0; i < num; i++ {
		dashboard := ui.Dashboard{
			ID:          generateUUID(t),
			CreatedBy:   createdBy,
			Name:        namegen.Generate(),
			Description: namegen.Generate(),
			Layout:      namegen.Generate(),
			Metadata:    namegen.Generate(),
			CreatedAt:   now.Add(time.Duration(i) * time.Second),
		}
		_, err := repo.Create(context.Background(), dashboard)
		require.Nil(t, err, fmt.Sprintf("create dashboard unexpected error: %s", err))
		dashboard.Layout = ""
		dashboard.Metadata = ""
		items = append(items, dashboard)
	}
	slices.Reverse(items)

	cases := []struct {
		desc     string
		page     ui.DashboardPageMeta
		response ui.DashboardPage
		err      error
	}{
		{
			desc: "retrieve dashboards",
			page: ui.DashboardPageMeta{
				Limit:     10,
				Offset:    0,
				CreatedBy: createdBy,
			},
			response: ui.DashboardPage{
				Offset:     0,
				Limit:      10,
				Total:      uint64(num),
				Dashboards: items[:10],
			},
			err: nil,
		},
		{
			desc: "retrieve dashboards with offset",
			page: ui.DashboardPageMeta{
				Limit:     10,
				Offset:    10,
				CreatedBy: createdBy,
			},
			response: ui.DashboardPage{
				Offset:     10,
				Limit:      10,
				Total:      uint64(num),
				Dashboards: items[10:20],
			},
			err: nil,
		},
		{
			desc: "retrieve dashboards with offset out of range",
			page: ui.DashboardPageMeta{
				Limit:     10,
				Offset:    1000,
				CreatedBy: createdBy,
			},
			response: ui.DashboardPage{
				Offset:     1000,
				Limit:      10,
				Total:      uint64(num),
				Dashboards: []ui.Dashboard(nil),
			},
			err: nil,
		},
		{
			desc: "retrieve dashboards with limit out of range",
			page: ui.DashboardPageMeta{
				Limit:     1000,
				Offset:    0,
				CreatedBy: createdBy,
			},
			response: ui.DashboardPage{
				Offset:     0,
				Limit:      1000,
				Total:      uint64(num),
				Dashboards: items,
			},
			err: nil,
		},
		{
			desc: "retrieve dashboards with empty created by",
			page: ui.DashboardPageMeta{
				Limit:  10,
				Offset: 0,
			},
			response: ui.DashboardPage{
				Offset:     0,
				Limit:      10,
				Total:      0,
				Dashboards: []ui.Dashboard(nil),
			},
			err: nil,
		},
		{
			desc: "retrieve dashboards with empty page",
			page: ui.DashboardPageMeta{},
			response: ui.DashboardPage{
				Offset:     0,
				Limit:      0,
				Total:      0,
				Dashboards: []ui.Dashboard(nil),
			},
			err: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			dashboards, err := repo.RetrieveAll(context.Background(), tc.page)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s to contain: %s", err, tc.err))
			if err == nil {
				assert.Equal(t, tc.response, dashboards)
			}
		})
	}
}

func TestUpdate(t *testing.T) {
	t.Cleanup(func() {
		_, err := db.Exec("DELETE FROM dashboards")
		require.Nil(t, err, fmt.Sprintf("clean dashboards unexpected error: %s", err))
	})

	dashboard := ui.Dashboard{
		ID:          generateUUID(t),
		CreatedBy:   generateUUID(t),
		Name:        namegen.Generate(),
		Description: namegen.Generate(),
		Layout:      namegen.Generate(),
		Metadata:    namegen.Generate(),
		CreatedAt:   time.Now().UTC().Truncate(time.Millisecond),
	}
	_, err := repo.Create(context.Background(), dashboard)
	require.Nil(t, err, fmt.Sprintf("create dashboard unexpected error: %s", err))

	cases := []struct {
		desc        string
		dashboardID string
		userID      string
		dashboard   ui.DashboardReq
		err         error
	}{
		{
			desc:        "update existing dashboard",
			dashboardID: dashboard.ID,
			userID:      dashboard.CreatedBy,
			dashboard: ui.DashboardReq{
				Name:        namegen.Generate(),
				Description: namegen.Generate(),
				Layout:      namegen.Generate(),
				Metadata:    namegen.Generate(),
			},
			err: nil,
		},
		{
			desc:        "update existing dashboard with empty name",
			dashboardID: dashboard.ID,
			userID:      dashboard.CreatedBy,
			dashboard: ui.DashboardReq{
				Name:        "",
				Description: namegen.Generate(),
				Layout:      namegen.Generate(),
				Metadata:    namegen.Generate(),
			},
			err: nil,
		},
		{
			desc:        "update existing dashboard with empty description",
			dashboardID: dashboard.ID,
			userID:      dashboard.CreatedBy,
			dashboard: ui.DashboardReq{
				Name:        namegen.Generate(),
				Description: "",
				Layout:      namegen.Generate(),
				Metadata:    namegen.Generate(),
			},
			err: nil,
		},
		{
			desc:        "update existing dashboard with empty layout",
			dashboardID: dashboard.ID,
			userID:      dashboard.CreatedBy,
			dashboard: ui.DashboardReq{
				Name:        namegen.Generate(),
				Description: namegen.Generate(),
				Layout:      "",
				Metadata:    namegen.Generate(),
			},
			err: nil,
		},
		{
			desc:        "update existing dashboard with empty metadata",
			dashboardID: dashboard.ID,
			userID:      dashboard.CreatedBy,
			dashboard: ui.DashboardReq{
				Name:        namegen.Generate(),
				Description: namegen.Generate(),
				Layout:      namegen.Generate(),
				Metadata:    "",
			},
			err: nil,
		},
		{
			desc:        "update existing dashboard with empty dashboard request",
			dashboardID: dashboard.ID,
			userID:      dashboard.CreatedBy,
			dashboard:   ui.DashboardReq{},
			err:         postgres.ErrMalformedEntity,
		},
		{
			desc:        "update non-existing dashboard",
			dashboardID: generateUUID(t),
			userID:      generateUUID(t),
			dashboard: ui.DashboardReq{
				Name:        namegen.Generate(),
				Description: namegen.Generate(),
				Layout:      namegen.Generate(),
				Metadata:    namegen.Generate(),
			},
			err: postgres.ErrNotFound,
		},
		{
			desc:        "update existing dashboard with empty id",
			dashboardID: "",
			userID:      dashboard.CreatedBy,
			dashboard: ui.DashboardReq{
				Name:        namegen.Generate(),
				Description: namegen.Generate(),
				Layout:      namegen.Generate(),
				Metadata:    namegen.Generate(),
			},
			err: postgres.ErrNotFound,
		},
		{
			desc:        "update existing dashboard with empty created by",
			dashboardID: dashboard.ID,
			userID:      "",
			dashboard: ui.DashboardReq{
				Name:        namegen.Generate(),
				Description: namegen.Generate(),
				Layout:      namegen.Generate(),
				Metadata:    namegen.Generate(),
			},
			err: postgres.ErrNotFound,
		},
		{
			desc:        "update existing dashboard with malformed id",
			dashboardID: strings.Repeat("a", 37),
			userID:      dashboard.CreatedBy,
			dashboard: ui.DashboardReq{
				Name:        namegen.Generate(),
				Description: namegen.Generate(),
				Layout:      namegen.Generate(),
				Metadata:    namegen.Generate(),
			},
			err: postgres.ErrNotFound,
		},
		{
			desc:        "update existing dashboard with malformed created by",
			dashboardID: dashboard.ID,
			userID:      strings.Repeat("a", 37),
			dashboard: ui.DashboardReq{
				Name:        namegen.Generate(),
				Description: namegen.Generate(),
				Layout:      namegen.Generate(),
				Metadata:    namegen.Generate(),
			},
			err: postgres.ErrNotFound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := repo.Update(context.Background(), tc.dashboardID, tc.userID, tc.dashboard)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s to contain: %s", err, tc.err))
			if err == nil {
				rDashboard, err := repo.Retrieve(context.Background(), tc.dashboardID, tc.userID)
				require.Nil(t, err, fmt.Sprintf("retrieve dashboard unexpected error: %s", err))
				if tc.dashboard.Name != "" {
					assert.Equal(t, tc.dashboard.Name, rDashboard.Name)
				}
				if tc.dashboard.Description != "" {
					assert.Equal(t, tc.dashboard.Description, rDashboard.Description)
				}
				if tc.dashboard.Layout != "" {
					assert.Equal(t, tc.dashboard.Layout, rDashboard.Layout)
				}
				if tc.dashboard.Metadata != "" {
					assert.Equal(t, tc.dashboard.Metadata, rDashboard.Metadata)
				}
			}
		})
	}
}

func TestDelete(t *testing.T) {
	t.Cleanup(func() {
		_, err := db.Exec("DELETE FROM dashboards")
		require.Nil(t, err, fmt.Sprintf("clean dashboards unexpected error: %s", err))
	})

	dashboard := ui.Dashboard{
		ID:          generateUUID(t),
		CreatedBy:   generateUUID(t),
		Name:        namegen.Generate(),
		Description: namegen.Generate(),
		Layout:      namegen.Generate(),
		Metadata:    namegen.Generate(),
		CreatedAt:   time.Now().UTC().Truncate(time.Millisecond),
	}
	_, err := repo.Create(context.Background(), dashboard)
	require.Nil(t, err, fmt.Sprintf("create dashboard unexpected error: %s", err))

	cases := []struct {
		desc        string
		dashboardID string
		userID      string
		err         error
	}{
		{
			desc:        "delete existing dashboard",
			dashboardID: dashboard.ID,
			userID:      dashboard.CreatedBy,
			err:         nil,
		},
		{
			desc:        "delete non-existing dashboard",
			dashboardID: generateUUID(t),
			userID:      generateUUID(t),
			err:         postgres.ErrNotFound,
		},
		{
			desc:        "delete existing dashboard with empty id",
			dashboardID: "",
			userID:      dashboard.CreatedBy,
			err:         postgres.ErrNotFound,
		},
		{
			desc:        "delete existing dashboard with empty created by",
			dashboardID: dashboard.ID,
			userID:      "",
			err:         postgres.ErrNotFound,
		},
		{
			desc:        "delete existing dashboard with malformed id",
			dashboardID: strings.Repeat("a", 37),
			userID:      dashboard.CreatedBy,
			err:         postgres.ErrNotFound,
		},
		{
			desc:        "delete existing dashboard with malformed created by",
			dashboardID: dashboard.ID,
			userID:      strings.Repeat("a", 37),
			err:         postgres.ErrNotFound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			err := repo.Delete(context.Background(), tc.dashboardID, tc.userID)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s to contain: %s", err, tc.err))
		})
	}
}

func generateUUID(t *testing.T) string {
	idProvider := uuid.New()
	uuid, err := idProvider.ID()
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
	return uuid
}
