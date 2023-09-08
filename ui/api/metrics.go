// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

//go:build !test
// +build !test

package api

import (
	"context"
	"time"

	"github.com/ultravioletrs/mainflux-ui/ui"

	"github.com/go-kit/kit/metrics"
	"github.com/mainflux/mainflux/pkg/messaging"
	sdk "github.com/mainflux/mainflux/pkg/sdk/go"
)

var _ ui.Service = (*metricsMiddleware)(nil)

type metricsMiddleware struct {
	counter metrics.Counter
	latency metrics.Histogram
	svc     ui.Service
}

// MetricsMiddleware instruments adapter by tracking request count and latency.
func MetricsMiddleware(svc ui.Service, counter metrics.Counter, latency metrics.Histogram) ui.Service {
	return &metricsMiddleware{
		counter: counter,
		latency: latency,
		svc:     svc,
	}
}

// Index adds metrics middleware to index method.
func (mm *metricsMiddleware) Index(ctx context.Context, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "index").Add(1)
		mm.latency.With("method", "index").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Index(ctx, token)
}

// Login adds metrics middleware to login method.
func (mm *metricsMiddleware) Login(ctx context.Context) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "login").Add(1)
		mm.latency.With("method", "login").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Login(ctx)
}

// PasswordResetRequest adds metrics middleware to password reset request method.
func (mm *metricsMiddleware) PasswordResetRequest(ctx context.Context, email string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "password_reset_request").Add(1)
		mm.latency.With("method", "password_reset_request").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.PasswordResetRequest(ctx, email)
}

// PasswordReset adds metrics middleware to password reset method.
func (mm *metricsMiddleware) PasswordReset(ctx context.Context, token, password, confirmPassword string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "password_reset").Add(1)
		mm.latency.With("method", "password_reset").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.PasswordReset(ctx, token, password, confirmPassword)
}

// ShowPasswordReset adds metrics middleware to show password reset method.
func (mm *metricsMiddleware) ShowPasswordReset(ctx context.Context) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "show_password_reset").Add(1)
		mm.latency.With("method", "show_password_reset").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ShowPasswordReset(ctx)
}

// PasswordUpdate adds metrics middleware to password update method.
func (mm *metricsMiddleware) PasswordUpdate(ctx context.Context) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "password_update").Add(1)
		mm.latency.With("method", "password_update").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.PasswordUpdate(ctx)
}

// Token adds metrics middleware to token method.
func (mm *metricsMiddleware) Token(ctx context.Context, user sdk.User) (sdk.Token, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "token").Add(1)
		mm.latency.With("method", "token").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Token(ctx, user)
}

// RefreshToken adds metrics middleware to refresh token method.
func (mm *metricsMiddleware) RefreshToken(ctx context.Context, refreshToken string) (sdk.Token, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "refresh_token").Add(1)
		mm.latency.With("method", "refresh_token").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.RefreshToken(ctx, refreshToken)
}

// Logout adds metrics middleware to logout method.
func (mm *metricsMiddleware) Logout(ctx context.Context) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "logout").Add(1)
		mm.latency.With("method", "logout").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Logout(ctx)
}

// UserProfile adds metrics middleware to user profile method.
func (mm *metricsMiddleware) UserProfile(ctx context.Context, token string) (user sdk.User, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "user_profile").Add(1)
		mm.latency.With("method", "user_profile").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UserProfile(ctx, token)
}

// UpdatePassword adds metrics middleware to update password method.
func (mm *metricsMiddleware) UpdatePassword(ctx context.Context, token, oldPass, newPass string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_user_password").Add(1)
		mm.latency.With("method", "update_user_password").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdatePassword(ctx, token, oldPass, newPass)
}

// CreateUsers adds metrics middleware to create users method.
func (mm *metricsMiddleware) CreateUsers(ctx context.Context, token string, users ...sdk.User) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "create_users").Add(1)
		mm.latency.With("method", "create_users").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.CreateUsers(ctx, token, users...)
}

// ListUsers adds metrics middleware to list users method.
func (mm *metricsMiddleware) ListUsers(ctx context.Context, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_users").Add(1)
		mm.latency.With("method", "list_users").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListUsers(ctx, token)
}

// ViewUser adds metrics middleware to view user method.
func (mm *metricsMiddleware) ViewUser(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "view_user").Add(1)
		mm.latency.With("method", "view_user").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ViewUser(ctx, token, id)
}

// UpdateUser adds metrics middleware to update user method.
func (mm *metricsMiddleware) UpdateUser(ctx context.Context, token, id string, user sdk.User) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_user").Add(1)
		mm.latency.With("method", "update_user").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateUser(ctx, token, id, user)
}

// UpdateUserTags adds metrics middleware to update user tags method.
func (mm *metricsMiddleware) UpdateUserTags(ctx context.Context, token, id string, user sdk.User) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_user_tags").Add(1)
		mm.latency.With("method", "update_user_tags").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateUserTags(ctx, token, id, user)
}

// UpdateUserIdentity adds metrics middleware to update user identity method.
func (mm *metricsMiddleware) UpdateUserIdentity(ctx context.Context, token, id string, user sdk.User) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_user_identity").Add(1)
		mm.latency.With("method", "update_user_identity").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateUserIdentity(ctx, token, id, user)
}

// UpdateUserOwner adds metrics middleware to update user owner method.
func (mm *metricsMiddleware) UpdateUserOwner(ctx context.Context, token, id string, user sdk.User) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_user_owner").Add(1)
		mm.latency.With("method", "update_user_owner").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateUserOwner(ctx, token, id, user)
}

// EnableUser adds metrics middleware to enable user method.
func (mm *metricsMiddleware) EnableUser(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "enable_user").Add(1)
		mm.latency.With("method", "enable_user").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.EnableUser(ctx, token, id)
}

// DisableUser adds metrics middleware to disable user method.
func (mm *metricsMiddleware) DisableUser(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "disable_user").Add(1)
		mm.latency.With("method", "disable_user").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DisableUser(ctx, token, id)
}

// CreateThings adds metrics middleware to create things method.
func (mm *metricsMiddleware) CreateThings(ctx context.Context, token string, things ...sdk.Thing) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "create_things").Add(1)
		mm.latency.With("method", "create_things").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.CreateThings(ctx, token, things...)
}

// ListThings adds metrics middleware to list things method.
func (mm *metricsMiddleware) ListThings(ctx context.Context, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_things").Add(1)
		mm.latency.With("method", "list_things").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListThings(ctx, token)
}

// viewThing adds metrics middleware to view thing method.
func (mm *metricsMiddleware) ViewThing(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "view_thing").Add(1)
		mm.latency.With("method", "view_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ViewThing(ctx, token, id)
}

// UpdateThing adds metrics middleware to update thing method.
func (mm *metricsMiddleware) UpdateThing(ctx context.Context, token, id string, thing sdk.Thing) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_thing").Add(1)
		mm.latency.With("method", "update_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateThing(ctx, token, id, thing)
}

// UpdateThingTags adds metrics middleware to update thing tags method.
func (mm *metricsMiddleware) UpdateThingTags(ctx context.Context, token, id string, thing sdk.Thing) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_thing_tags").Add(1)
		mm.latency.With("method", "update_thing_tags").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateThingTags(ctx, token, id, thing)
}

// UpdateThingSecret adds metrics middleware to update thing secret method.
func (mm *metricsMiddleware) UpdateThingSecret(ctx context.Context, token, id, secret string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_thing_secret").Add(1)
		mm.latency.With("method", "update_thing_secret").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateThingSecret(ctx, token, id, secret)
}

// EnableThing adds metrics middleware to enable thing method.
func (mm *metricsMiddleware) EnableThing(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "enable_thing").Add(1)
		mm.latency.With("method", "enable_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.EnableThing(ctx, token, id)
}

// DisableThing adds metrics middleware to disable thing method.
func (mm *metricsMiddleware) DisableThing(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "disable_thing").Add(1)
		mm.latency.With("method", "disable_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DisableThing(ctx, token, id)
}

// UpdateThingOwner adds metrics middleware to update thing owner method.
func (mm *metricsMiddleware) UpdateThingOwner(ctx context.Context, token, id string, thing sdk.Thing) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_thing_owner").Add(1)
		mm.latency.With("method", "update_thing_owner").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateThingOwner(ctx, token, id, thing)
}

// CreateChannels adds metrics middleware to create channels method.
func (mm *metricsMiddleware) CreateChannels(ctx context.Context, token string, channels ...sdk.Channel) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "create_channels").Add(1)
		mm.latency.With("method", "create_channels").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.CreateChannels(ctx, token, channels...)
}

// ViewChannel adds metrics middleware to view channels method.
func (mm *metricsMiddleware) ViewChannel(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "view_channel").Add(1)
		mm.latency.With("method", "view_channel").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ViewChannel(ctx, token, id)
}

// UpdateChannel adds metrics middleware to update channel method.
func (mm *metricsMiddleware) UpdateChannel(ctx context.Context, token, id string, channel sdk.Channel) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_channel").Add(1)
		mm.latency.With("method", "update_channel").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateChannel(ctx, token, id, channel)
}

// ListChannels adds metrics middleware to list channels method.
func (mm *metricsMiddleware) ListChannels(ctx context.Context, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_channels").Add(1)
		mm.latency.With("method", "list_channels").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListChannels(ctx, token)
}

// EnableChannel adds metrics middleware to enable channel method.
func (mm *metricsMiddleware) EnableChannel(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "enable_channel").Add(1)
		mm.latency.With("method", "enable_channel").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.EnableChannel(ctx, token, id)
}

// DisableChannel adds metrics middleware to disable channel method.
func (mm *metricsMiddleware) DisableChannel(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "disable_channel").Add(1)
		mm.latency.With("method", "disable_channel").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DisableChannel(ctx, token, id)
}

// Connect adds metrics middleware to connect method.
func (mm *metricsMiddleware) Connect(ctx context.Context, token string, connIDs sdk.ConnectionIDs) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "connect").Add(1)
		mm.latency.With("method", "connect").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Connect(ctx, token, connIDs)
}

// Disconnect adds metrics middleware to disconnect method.
func (mm *metricsMiddleware) Disconnect(ctx context.Context, token string, connIDs sdk.ConnectionIDs) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "disconnect").Add(1)
		mm.latency.With("method", "disconnect").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Disconnect(ctx, token, connIDs)
}

// ListThingsByChannel adds metrics middleware to list things by channel method.
func (mm *metricsMiddleware) ListThingsByChannel(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_things_by_channel").Add(1)
		mm.latency.With("method", "list_things_by_channel").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListThingsByChannel(ctx, token, id)
}

// ListChannelsByThing adds metrics middleware to list channels by thing method.
func (mm *metricsMiddleware) ListChannelsByThing(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_channels_by_thing").Add(1)
		mm.latency.With("method", "list_channels_by_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListChannelsByThing(ctx, token, id)
}

// ConnectThing adds metrics middleware to connect thing method.
func (mm *metricsMiddleware) ConnectThing(ctx context.Context, token string, connIDs sdk.ConnectionIDs) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "connect_thing").Add(1)
		mm.latency.With("method", "connect_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ConnectThing(ctx, token, connIDs)
}

// ShareThing adds metrics middleware to share thing method.
func (mm *metricsMiddleware) ShareThing(ctx context.Context, token, chanID, userID string, actions []string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "share_thing").Add(1)
		mm.latency.With("method", "share_thing").Observe(float64(time.Since(begin).Seconds()))
	}(time.Now())

	return mm.svc.ShareThing(ctx, token, chanID, userID, actions)
}

// DisconnectThing adds metrics middleware to disconnect thing method.
func (mm *metricsMiddleware) DisconnectThing(ctx context.Context, thID, chID, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "disconnect_thing").Add(1)
		mm.latency.With("method", "disconnect_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DisconnectThing(ctx, thID, chID, token)
}

// ConnectChannel adds metrics middleware to connect channel method.
func (mm *metricsMiddleware) ConnectChannel(ctx context.Context, token string, connIDs sdk.ConnectionIDs) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "connect_channel").Add(1)
		mm.latency.With("method", "connect_channel").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ConnectChannel(ctx, token, connIDs)
}

// DisconnectChannel adds metrics middleware to disconnect channel method.
func (mm *metricsMiddleware) DisconnectChannel(ctx context.Context, thID, chID, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "disconnect_channel").Add(1)
		mm.latency.With("method", "disconnect_channel").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DisconnectChannel(ctx, thID, chID, token)
}

// ListThingsPolicies adds metrics middleware to list things policies method.
func (mm *metricsMiddleware) ListThingsPolicies(ctx context.Context, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_things_policies").Add(1)
		mm.latency.With("method", "list_things_policies").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListThingsPolicies(ctx, token)
}

// AddThingsPolicy adds metrics middleware to add things policy method.
func (mm *metricsMiddleware) AddThingsPolicy(ctx context.Context, token string, policy sdk.Policy) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "add_things_policy").Add(1)
		mm.latency.With("method", "add_things_policy").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.AddThingsPolicy(ctx, token, policy)
}

// DeleteThingsPolicy adds metrics middleware to delete things policy method.
func (mm *metricsMiddleware) DeleteThingsPolicy(ctx context.Context, token string, policy sdk.Policy) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "delete_things_policy").Add(1)
		mm.latency.With("method", "delete_things_policy").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DeleteThingsPolicy(ctx, token, policy)
}

// UpdateThingsPolicy adds metrics middleware to update things policy method.
func (mm *metricsMiddleware) UpdateThingsPolicy(ctx context.Context, token string, policy sdk.Policy) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_things_policy").Add(1)
		mm.latency.With("method", "update_things_policy").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateThingsPolicy(ctx, token, policy)
}

// CreateGroups adds metrics middleware to create groups method.
func (mm *metricsMiddleware) CreateGroups(ctx context.Context, token string, groups ...sdk.Group) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "create_groups").Add(1)
		mm.latency.With("method", "create_groups").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.CreateGroups(ctx, token, groups...)
}

// ListGroups adds metrics middleware to list groups method.
func (mm *metricsMiddleware) ListGroups(ctx context.Context, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_groups").Add(1)
		mm.latency.With("method", "list_groups").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListGroups(ctx, token)
}

// ViewGroup adds metrics middleware to view group method.
func (mm *metricsMiddleware) ViewGroup(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "view_group").Add(1)
		mm.latency.With("method", "view_group").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ViewGroup(ctx, token, id)
}

// ListGroupMembers adds metrics middleware to list group members method.
func (mm *metricsMiddleware) ListGroupMembers(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_group_members").Add(1)
		mm.latency.With("method", "list_group_members").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListGroupMembers(ctx, token, id)
}

// UpdateGroup adds metrics middleware to update group method.
func (mm *metricsMiddleware) UpdateGroup(ctx context.Context, token, id string, group sdk.Group) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_group").Add(1)
		mm.latency.With("method", "update_group").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateGroup(ctx, token, id, group)
}

// Assign adds metrics middleware to assign method.
func (mm *metricsMiddleware) Assign(ctx context.Context, token, groupID, memberID string, memberType []string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "assign").Add(1)
		mm.latency.With("method", "assign").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Assign(ctx, token, groupID, memberID, memberType)
}

// Unassign adds metrics middleware to unassign method.
func (mm *metricsMiddleware) Unassign(ctx context.Context, token, groupID, memberID string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "unassign").Add(1)
		mm.latency.With("method", "unassign").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Unassign(ctx, token, groupID, memberID)
}

// Enable group adds metrics middleware to enable group method.
func (mm *metricsMiddleware) EnableGroup(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "enable_group").Add(1)
		mm.latency.With("method", "enable_group").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.EnableGroup(ctx, token, id)
}

// DisableGroup adds metrics middleware to disable group method.
func (mm *metricsMiddleware) DisableGroup(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "disable_group").Add(1)
		mm.latency.With("method", "disable_group").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DisableGroup(ctx, token, id)
}

// AddPolicy adds metrics middleware to add policy method.
func (mm *metricsMiddleware) AddPolicy(ctx context.Context, token string, policy sdk.Policy) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "add_policy").Add(1)
		mm.latency.With("method", "add_policy").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.AddPolicy(ctx, token, policy)
}

// ListPolicies adds metrics middleware to list policies method.
func (mm *metricsMiddleware) ListPolicies(ctx context.Context, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_policies").Add(1)
		mm.latency.With("method", "list_policies").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListPolicies(ctx, token)
}

// UpdatePolicy adds metrics middleware to update policy method.
func (mm *metricsMiddleware) UpdatePolicy(ctx context.Context, token string, policy sdk.Policy) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_policy").Add(1)
		mm.latency.With("method", "update_policy").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdatePolicy(ctx, token, policy)
}

// DeletePolicy adds metrics middleware to delete policy method.
func (mm *metricsMiddleware) DeletePolicy(ctx context.Context, token string, policy sdk.Policy) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "delete_policy").Add(1)
		mm.latency.With("method", "delete_policy").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DeletePolicy(ctx, token, policy)
}

// Publish adds metrics middleware to publish method.
func (mm *metricsMiddleware) Publish(ctx context.Context, token, thingKey string, msg *messaging.Message) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "publish").Add(1)
		mm.latency.With("method", "publish").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Publish(ctx, token, thingKey, msg)
}

// ReadMessage adds metrics middleware to read message method.
func (mm *metricsMiddleware) ReadMessage(ctx context.Context, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "read_message").Add(1)
		mm.latency.With("method", "read_message").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ReadMessage(ctx, token)
}

// WsConnection adds metrics middleware to ws connection method.
func (mm *metricsMiddleware) WsConnection(ctx context.Context, token, chID, thKey string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "ws_connection").Add(1)
		mm.latency.With("method", "ws_connection").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.WsConnection(ctx, token, chID, thKey)
}

// ListDeletedClients adds metrics middleware to list deleted clients method.
func (mm *metricsMiddleware) ListDeletedClients(ctx context.Context, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_deleted_clients").Add(1)
		mm.latency.With("method", "list_deleted_clients").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListDeletedClients(ctx, token)
}

// GetRemoteTerminal adds metrics middleware to get remote terminal method.
func (mm *metricsMiddleware) GetRemoteTerminal(ctx context.Context, id string) ([]byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "remote_terminal").Add(1)
		mm.latency.With("method", "remote_terminal").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.GetRemoteTerminal(ctx, id)
}

// ProcessTerminalCommand adds metrics middleware to process terminal command method.
func (mm *metricsMiddleware) ProcessTerminalCommand(ctx context.Context, id, token, command string, res chan string) error {
	defer func(begin time.Time) {
		mm.counter.With("method", "remote_terminal").Add(1)
		mm.latency.With("method", "remote_terminal").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ProcessTerminalCommand(ctx, id, token, command, res)
}

// CreateBootstrap adds metrics middleware to create bootstrap method.
func (mm *metricsMiddleware) CreateBootstrap(ctx context.Context, token string, config ...sdk.BootstrapConfig) ([]byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "create_bootstrap").Add(1)
		mm.latency.With("method", "create_bootstrap").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.CreateBootstrap(ctx, token, config...)
}

// DeleteBootstrap adds metrics middleware to delete bootstrap method.
func (mm *metricsMiddleware) DeleteBootstrap(ctx context.Context, token string, id string) ([]byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "delete_bootstrap").Add(1)
		mm.latency.With("method", "delete_bootstrap").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DeleteBootstrap(ctx, token, id)
}

// ListBootstrap adds metrics middleware to list bootstrap method.
func (mm *metricsMiddleware) ListBootstrap(ctx context.Context, token string) ([]byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_bootstrap").Add(1)
		mm.latency.With("method", "list_bootstrap").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListBootstrap(ctx, token)
}

// UpdateBootstrap adds metrics middleware to update bootstrap method.
func (mm *metricsMiddleware) UpdateBootstrap(ctx context.Context, token string, config sdk.BootstrapConfig) ([]byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_bootstrap").Add(1)
		mm.latency.With("method", "update_bootstrap").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateBootstrap(ctx, token, config)
}

// UpdateBootstrapCerts adds metrics middleware to update bootstrap certs method.
func (mm *metricsMiddleware) UpdateBootstrapCerts(ctx context.Context, token string, config sdk.BootstrapConfig) ([]byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_bootstrap_certs").Add(1)
		mm.latency.With("method", "update_bootstrap_certs").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateBootstrapCerts(ctx, token, config)
}

// UpdateBootstrapConnections adds metrics middleware to  update bootstrap connections method.
func (mm *metricsMiddleware) UpdateBootstrapConnections(ctx context.Context, token string, config sdk.BootstrapConfig) ([]byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_bootstrap_connections").Add(1)
		mm.latency.With("method", "update_bootstrap_connections").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateBootstrapConnections(ctx, token, config)
}

// ViewBootstrap adds metrics middleware to view bootstrap method.
func (mm *metricsMiddleware) ViewBootstrap(ctx context.Context, token string, id string) ([]byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "view_bootstrap").Add(1)
		mm.latency.With("method", "view_bootstrap").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ViewBootstrap(ctx, token, id)
}
