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
func (mm *metricsMiddleware) Index(token string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "index").Add(1)
		mm.latency.With("method", "index").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Index(token)
}

// Login adds metrics middleware to login method.
func (mm *metricsMiddleware) Login() (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "login").Add(1)
		mm.latency.With("method", "login").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Login()
}

// PasswordResetRequest adds metrics middleware to password reset request method.
func (mm *metricsMiddleware) PasswordResetRequest(email string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "password_reset_request").Add(1)
		mm.latency.With("method", "password_reset_request").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.PasswordResetRequest(email)
}

// PasswordReset adds metrics middleware to password reset method.
func (mm *metricsMiddleware) PasswordReset(token, password, confirmPassword string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "password_reset").Add(1)
		mm.latency.With("method", "password_reset").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.PasswordReset(token, password, confirmPassword)
}

// ShowPasswordReset adds metrics middleware to show password reset method.
func (mm *metricsMiddleware) ShowPasswordReset() (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "show_password_reset").Add(1)
		mm.latency.With("method", "show_password_reset").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ShowPasswordReset()
}

// PasswordUpdate adds metrics middleware to password update method.
func (mm *metricsMiddleware) PasswordUpdate(token string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "password_update").Add(1)
		mm.latency.With("method", "password_update").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.PasswordUpdate(token)
}

// Token adds metrics middleware to token method.
func (mm *metricsMiddleware) Token(user sdk.User) (sdk.Token, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "token").Add(1)
		mm.latency.With("method", "token").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Token(user)
}

// RefreshToken adds metrics middleware to refresh token method.
func (mm *metricsMiddleware) RefreshToken(refreshToken string) (sdk.Token, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "refresh_token").Add(1)
		mm.latency.With("method", "refresh_token").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.RefreshToken(refreshToken)
}

// Logout adds metrics middleware to logout method.
func (mm *metricsMiddleware) Logout() (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "logout").Add(1)
		mm.latency.With("method", "logout").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Logout()
}

// UserProfile adds metrics middleware to user profile method.
func (mm *metricsMiddleware) UserProfile(token string) (user sdk.User, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "user_profile").Add(1)
		mm.latency.With("method", "user_profile").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UserProfile(token)
}

// UpdatePassword adds metrics middleware to update password method.
func (mm *metricsMiddleware) UpdatePassword(token, oldPass, newPass string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_user_password").Add(1)
		mm.latency.With("method", "update_user_password").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdatePassword(token, oldPass, newPass)
}

// CreateUsers adds metrics middleware to create users method.
func (mm *metricsMiddleware) CreateUsers(token string, users ...sdk.User) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "create_users").Add(1)
		mm.latency.With("method", "create_users").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.CreateUsers(token, users...)
}

// ListUsers adds metrics middleware to list users method.
func (mm *metricsMiddleware) ListUsers(token string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_users").Add(1)
		mm.latency.With("method", "list_users").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListUsers(token, page, limit)
}

// ViewUser adds metrics middleware to view user method.
func (mm *metricsMiddleware) ViewUser(token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "view_user").Add(1)
		mm.latency.With("method", "view_user").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ViewUser(token, id)
}

// UpdateUser adds metrics middleware to update user method.
func (mm *metricsMiddleware) UpdateUser(token, id string, user sdk.User) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_user").Add(1)
		mm.latency.With("method", "update_user").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateUser(token, id, user)
}

// UpdateUserTags adds metrics middleware to update user tags method.
func (mm *metricsMiddleware) UpdateUserTags(token, id string, user sdk.User) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_user_tags").Add(1)
		mm.latency.With("method", "update_user_tags").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateUserTags(token, id, user)
}

// UpdateUserIdentity adds metrics middleware to update user identity method.
func (mm *metricsMiddleware) UpdateUserIdentity(token, id string, user sdk.User) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_user_identity").Add(1)
		mm.latency.With("method", "update_user_identity").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateUserIdentity(token, id, user)
}

// UpdateUserOwner adds metrics middleware to update user owner method.
func (mm *metricsMiddleware) UpdateUserOwner(token, id string, user sdk.User) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_user_owner").Add(1)
		mm.latency.With("method", "update_user_owner").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateUserOwner(token, id, user)
}

// EnableUser adds metrics middleware to enable user method.
func (mm *metricsMiddleware) EnableUser(token, id string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "enable_user").Add(1)
		mm.latency.With("method", "enable_user").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.EnableUser(token, id)
}

// DisableUser adds metrics middleware to disable user method.
func (mm *metricsMiddleware) DisableUser(token, id string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "disable_user").Add(1)
		mm.latency.With("method", "disable_user").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DisableUser(token, id)
}

// CreateThings adds metrics middleware to create things method.
func (mm *metricsMiddleware) CreateThings(token string, things ...sdk.Thing) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "create_things").Add(1)
		mm.latency.With("method", "create_things").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.CreateThings(token, things...)
}

// ListThings adds metrics middleware to list things method.
func (mm *metricsMiddleware) ListThings(token string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_things").Add(1)
		mm.latency.With("method", "list_things").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListThings(token, page, limit)
}

// viewThing adds metrics middleware to view thing method.
func (mm *metricsMiddleware) ViewThing(token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "view_thing").Add(1)
		mm.latency.With("method", "view_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ViewThing(token, id)
}

// UpdateThing adds metrics middleware to update thing method.
func (mm *metricsMiddleware) UpdateThing(token, id string, thing sdk.Thing) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_thing").Add(1)
		mm.latency.With("method", "update_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateThing(token, id, thing)
}

// UpdateThingTags adds metrics middleware to update thing tags method.
func (mm *metricsMiddleware) UpdateThingTags(token, id string, thing sdk.Thing) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_thing_tags").Add(1)
		mm.latency.With("method", "update_thing_tags").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateThingTags(token, id, thing)
}

// UpdateThingSecret adds metrics middleware to update thing secret method.
func (mm *metricsMiddleware) UpdateThingSecret(token, id, secret string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_thing_secret").Add(1)
		mm.latency.With("method", "update_thing_secret").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateThingSecret(token, id, secret)
}

// EnableThing adds metrics middleware to enable thing method.
func (mm *metricsMiddleware) EnableThing(token, id string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "enable_thing").Add(1)
		mm.latency.With("method", "enable_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.EnableThing(token, id)
}

// DisableThing adds metrics middleware to disable thing method.
func (mm *metricsMiddleware) DisableThing(token, id string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "disable_thing").Add(1)
		mm.latency.With("method", "disable_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DisableThing(token, id)
}

// UpdateThingOwner adds metrics middleware to update thing owner method.
func (mm *metricsMiddleware) UpdateThingOwner(token string, thing sdk.Thing) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_thing_owner").Add(1)
		mm.latency.With("method", "update_thing_owner").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateThingOwner(token, thing)
}

// CreateChannels adds metrics middleware to create channels method.
func (mm *metricsMiddleware) CreateChannels(token string, channels ...sdk.Channel) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "create_channels").Add(1)
		mm.latency.With("method", "create_channels").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.CreateChannels(token, channels...)
}

// ViewChannel adds metrics middleware to view channels method.
func (mm *metricsMiddleware) ViewChannel(token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "view_channel").Add(1)
		mm.latency.With("method", "view_channel").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ViewChannel(token, id)
}

// UpdateChannel adds metrics middleware to update channel method.
func (mm *metricsMiddleware) UpdateChannel(token, id string, channel sdk.Channel) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_channel").Add(1)
		mm.latency.With("method", "update_channel").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateChannel(token, id, channel)
}

// ListChannels adds metrics middleware to list channels method.
func (mm *metricsMiddleware) ListChannels(token string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_channels").Add(1)
		mm.latency.With("method", "list_channels").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListChannels(token, page, limit)
}

// EnableChannel adds metrics middleware to enable channel method.
func (mm *metricsMiddleware) EnableChannel(token, id string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "enable_channel").Add(1)
		mm.latency.With("method", "enable_channel").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.EnableChannel(token, id)
}

// DisableChannel adds metrics middleware to disable channel method.
func (mm *metricsMiddleware) DisableChannel(token, id string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "disable_channel").Add(1)
		mm.latency.With("method", "disable_channel").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DisableChannel(token, id)
}

// Connect adds metrics middleware to connect method.
func (mm *metricsMiddleware) Connect(token string, connIDs sdk.ConnectionIDs) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "connect").Add(1)
		mm.latency.With("method", "connect").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Connect(token, connIDs)
}

// Disconnect adds metrics middleware to disconnect method.
func (mm *metricsMiddleware) Disconnect(token string, connIDs sdk.ConnectionIDs) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "disconnect").Add(1)
		mm.latency.With("method", "disconnect").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Disconnect(token, connIDs)
}

// ListThingsByChannel adds metrics middleware to list things by channel method.
func (mm *metricsMiddleware) ListThingsByChannel(token, id string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_things_by_channel").Add(1)
		mm.latency.With("method", "list_things_by_channel").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListThingsByChannel(token, id, page, limit)
}

// ListChannelsByThing adds metrics middleware to list channels by thing method.
func (mm *metricsMiddleware) ListChannelsByThing(token, id string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_channels_by_thing").Add(1)
		mm.latency.With("method", "list_channels_by_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListChannelsByThing(token, id, page, limit)
}

// ConnectThing adds metrics middleware to connect thing method.
func (mm *metricsMiddleware) ConnectThing(token string, connIDs sdk.ConnectionIDs) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "connect_thing").Add(1)
		mm.latency.With("method", "connect_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ConnectThing(token, connIDs)
}

// ShareThing adds metrics middleware to share thing method.
func (mm *metricsMiddleware) ShareThing(token, chanID, userID string, actions []string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "share_thing").Add(1)
		mm.latency.With("method", "share_thing").Observe(float64(time.Since(begin).Seconds()))
	}(time.Now())

	return mm.svc.ShareThing(token, chanID, userID, actions)
}

// DisconnectThing adds metrics middleware to disconnect thing method.
func (mm *metricsMiddleware) DisconnectThing(thID, chID, token string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "disconnect_thing").Add(1)
		mm.latency.With("method", "disconnect_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DisconnectThing(thID, chID, token)
}

// ConnectChannel adds metrics middleware to connect channel method.
func (mm *metricsMiddleware) ConnectChannel(token string, connIDs sdk.ConnectionIDs) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "connect_channel").Add(1)
		mm.latency.With("method", "connect_channel").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ConnectChannel(token, connIDs)
}

// DisconnectChannel adds metrics middleware to disconnect channel method.
func (mm *metricsMiddleware) DisconnectChannel(thID, chID, token string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "disconnect_channel").Add(1)
		mm.latency.With("method", "disconnect_channel").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DisconnectChannel(thID, chID, token)
}

// ListThingsPolicies adds metrics middleware to list things policies method.
func (mm *metricsMiddleware) ListThingsPolicies(token string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_things_policies").Add(1)
		mm.latency.With("method", "list_things_policies").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListThingsPolicies(token, page, limit)
}

// AddThingsPolicy adds metrics middleware to add things policy method.
func (mm *metricsMiddleware) AddThingsPolicy(token string, policy sdk.Policy) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "add_things_policy").Add(1)
		mm.latency.With("method", "add_things_policy").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.AddThingsPolicy(token, policy)
}

// DeleteThingsPolicy adds metrics middleware to delete things policy method.
func (mm *metricsMiddleware) DeleteThingsPolicy(token string, policy sdk.Policy) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "delete_things_policy").Add(1)
		mm.latency.With("method", "delete_things_policy").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DeleteThingsPolicy(token, policy)
}

// UpdateThingsPolicy adds metrics middleware to update things policy method.
func (mm *metricsMiddleware) UpdateThingsPolicy(token string, policy sdk.Policy) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_things_policy").Add(1)
		mm.latency.With("method", "update_things_policy").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateThingsPolicy(token, policy)
}

// CreateGroups adds metrics middleware to create groups method.
func (mm *metricsMiddleware) CreateGroups(token string, groups ...sdk.Group) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "create_groups").Add(1)
		mm.latency.With("method", "create_groups").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.CreateGroups(token, groups...)
}

// ListGroups adds metrics middleware to list groups method.
func (mm *metricsMiddleware) ListGroups(token string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_groups").Add(1)
		mm.latency.With("method", "list_groups").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListGroups(token, page, limit)
}

// ViewGroup adds metrics middleware to view group method.
func (mm *metricsMiddleware) ViewGroup(token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "view_group").Add(1)
		mm.latency.With("method", "view_group").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ViewGroup(token, id)
}

// ListGroupMembers adds metrics middleware to list group members method.
func (mm *metricsMiddleware) ListGroupMembers(token, id string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_group_members").Add(1)
		mm.latency.With("method", "list_group_members").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListGroupMembers(token, id, page, limit)
}

// UpdateGroup adds metrics middleware to update group method.
func (mm *metricsMiddleware) UpdateGroup(token, id string, group sdk.Group) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_group").Add(1)
		mm.latency.With("method", "update_group").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateGroup(token, id, group)
}

// Assign adds metrics middleware to assign method.
func (mm *metricsMiddleware) Assign(token, groupID, memberID string, memberType []string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "assign").Add(1)
		mm.latency.With("method", "assign").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Assign(token, groupID, memberID, memberType)
}

// Unassign adds metrics middleware to unassign method.
func (mm *metricsMiddleware) Unassign(token, groupID, memberID string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "unassign").Add(1)
		mm.latency.With("method", "unassign").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Unassign(token, groupID, memberID)
}

// Enable group adds metrics middleware to enable group method.
func (mm *metricsMiddleware) EnableGroup(token, id string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "enable_group").Add(1)
		mm.latency.With("method", "enable_group").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.EnableGroup(token, id)
}

// DisableGroup adds metrics middleware to disable group method.
func (mm *metricsMiddleware) DisableGroup(token, id string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "disable_group").Add(1)
		mm.latency.With("method", "disable_group").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DisableGroup(token, id)
}

// AddPolicy adds metrics middleware to add policy method.
func (mm *metricsMiddleware) AddPolicy(token string, policy sdk.Policy) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "add_policy").Add(1)
		mm.latency.With("method", "add_policy").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.AddPolicy(token, policy)
}

// ListPolicies adds metrics middleware to list policies method.
func (mm *metricsMiddleware) ListPolicies(token string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_policies").Add(1)
		mm.latency.With("method", "list_policies").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListPolicies(token, page, limit)
}

// UpdatePolicy adds metrics middleware to update policy method.
func (mm *metricsMiddleware) UpdatePolicy(token string, policy sdk.Policy) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_policy").Add(1)
		mm.latency.With("method", "update_policy").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdatePolicy(token, policy)
}

// DeletePolicy adds metrics middleware to delete policy method.
func (mm *metricsMiddleware) DeletePolicy(token string, policy sdk.Policy) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "delete_policy").Add(1)
		mm.latency.With("method", "delete_policy").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DeletePolicy(token, policy)
}

// Publish adds metrics middleware to publish method.
func (mm *metricsMiddleware) Publish(token, thingKey string, msg *messaging.Message) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "publish").Add(1)
		mm.latency.With("method", "publish").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Publish(token, thingKey, msg)
}

// ReadMessage adds metrics middleware to read message method.
func (mm *metricsMiddleware) ReadMessage(token string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "read_message").Add(1)
		mm.latency.With("method", "read_message").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ReadMessage(token)
}

// WsConnection adds metrics middleware to ws connection method.
func (mm *metricsMiddleware) WsConnection(token, chID, thKey string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "ws_connection").Add(1)
		mm.latency.With("method", "ws_connection").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.WsConnection(token, chID, thKey)
}

// GetRemoteTerminal adds metrics middleware to get remote terminal method.
func (mm *metricsMiddleware) GetRemoteTerminal(id, token string) ([]byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "remote_terminal").Add(1)
		mm.latency.With("method", "remote_terminal").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.GetRemoteTerminal(id, token)
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
func (mm *metricsMiddleware) CreateBootstrap(token string, config ...sdk.BootstrapConfig) error {
	defer func(begin time.Time) {
		mm.counter.With("method", "create_bootstrap").Add(1)
		mm.latency.With("method", "create_bootstrap").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.CreateBootstrap(token, config...)
}

// DeleteBootstrap adds metrics middleware to delete bootstrap method.
func (mm *metricsMiddleware) DeleteBootstrap(token string, id string) error {
	defer func(begin time.Time) {
		mm.counter.With("method", "delete_bootstrap").Add(1)
		mm.latency.With("method", "delete_bootstrap").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DeleteBootstrap(token, id)
}

// ListBootstrap adds metrics middleware to list bootstrap method.
func (mm *metricsMiddleware) ListBootstrap(token string, page, limit uint64) ([]byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_bootstrap").Add(1)
		mm.latency.With("method", "list_bootstrap").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListBootstrap(token, page, limit)
}

// UpdateBootstrap adds metrics middleware to update bootstrap method.
func (mm *metricsMiddleware) UpdateBootstrap(token string, config sdk.BootstrapConfig) error {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_bootstrap").Add(1)
		mm.latency.With("method", "update_bootstrap").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateBootstrap(token, config)
}

// UpdateBootstrapCerts adds metrics middleware to update bootstrap certs method.
func (mm *metricsMiddleware) UpdateBootstrapCerts(token string, config sdk.BootstrapConfig) error {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_bootstrap_certs").Add(1)
		mm.latency.With("method", "update_bootstrap_certs").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateBootstrapCerts(token, config)
}

// UpdateBootstrapConnections adds metrics middleware to  update bootstrap connections method.
func (mm *metricsMiddleware) UpdateBootstrapConnections(token string, config sdk.BootstrapConfig) error {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_bootstrap_connections").Add(1)
		mm.latency.With("method", "update_bootstrap_connections").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateBootstrapConnections(token, config)
}

// ViewBootstrap adds metrics middleware to view bootstrap method.
func (mm *metricsMiddleware) ViewBootstrap(token string, id string) ([]byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "view_bootstrap").Add(1)
		mm.latency.With("method", "view_bootstrap").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ViewBootstrap(token, id)
}

func (mm *metricsMiddleware) GetEntities(token, item, name string, page, limit uint64) ([]byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "get_entities").Add(1)
		mm.latency.With("method", "get_entities").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.GetEntities(token, item, name, page, limit)
}
