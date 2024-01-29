// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"time"

	"github.com/absmach/magistrala-ui/ui"
	sdk "github.com/absmach/magistrala/pkg/sdk/go"
	"github.com/go-kit/kit/metrics"
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

// Logout adds metrics middleware to logout method.
func (mm *metricsMiddleware) Logout() (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "logout").Add(1)
		mm.latency.With("method", "logout").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Logout()
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

// UpdatePassword adds metrics middleware to update password method.
func (mm *metricsMiddleware) UpdatePassword(token, oldPass, newPass string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_user_password").Add(1)
		mm.latency.With("method", "update_user_password").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdatePassword(token, oldPass, newPass)
}

// Token adds metrics middleware to token method.
func (mm *metricsMiddleware) Token(login sdk.Login) (sdk.Token, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "token").Add(1)
		mm.latency.With("method", "token").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Token(login)
}

// RefreshToken adds metrics middleware to refresh token method.
func (mm *metricsMiddleware) RefreshToken(refreshToken string) (sdk.Token, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "refresh_token").Add(1)
		mm.latency.With("method", "refresh_token").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.RefreshToken(refreshToken)
}

// UserProfile adds metrics middleware to user profile method.
func (mm *metricsMiddleware) UserProfile(token string) ([]byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "user_profile").Add(1)
		mm.latency.With("method", "user_profile").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UserProfile(token)
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
func (mm *metricsMiddleware) ListUsers(token, status string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_users").Add(1)
		mm.latency.With("method", "list_users").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListUsers(token, status, page, limit)
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
func (mm *metricsMiddleware) UpdateUser(token string, user sdk.User) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_user").Add(1)
		mm.latency.With("method", "update_user").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateUser(token, user)
}

// UpdateUserTags adds metrics middleware to update user tags method.
func (mm *metricsMiddleware) UpdateUserTags(token string, user sdk.User) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_user_tags").Add(1)
		mm.latency.With("method", "update_user_tags").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateUserTags(token, user)
}

// UpdateUserIdentity adds metrics middleware to update user identity method.
func (mm *metricsMiddleware) UpdateUserIdentity(token string, user sdk.User) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_user_identity").Add(1)
		mm.latency.With("method", "update_user_identity").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateUserIdentity(token, user)
}

// UpdateUserOwner adds metrics middleware to update user owner method.
func (mm *metricsMiddleware) UpdateUserOwner(token string, user sdk.User) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_user_owner").Add(1)
		mm.latency.With("method", "update_user_owner").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateUserOwner(token, user)
}

// UpdateUserRole adds metrics middleware to update user role method.
func (mm *metricsMiddleware) UpdateUserRole(token string, user sdk.User) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_user_role").Add(1)
		mm.latency.With("method", "update_user_role").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateUserRole(token, user)
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

// CreateThing adds metrics middleware to create things method.
func (mm *metricsMiddleware) CreateThing(thing sdk.Thing, token string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "create_thing").Add(1)
		mm.latency.With("method", "create_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.CreateThing(thing, token)
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
func (mm *metricsMiddleware) ListThings(token, status string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_things").Add(1)
		mm.latency.With("method", "list_things").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListThings(token, status, page, limit)
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
func (mm *metricsMiddleware) UpdateThing(token string, thing sdk.Thing) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_thing").Add(1)
		mm.latency.With("method", "update_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateThing(token, thing)
}

// UpdateThingTags adds metrics middleware to update thing tags method.
func (mm *metricsMiddleware) UpdateThingTags(token string, thing sdk.Thing) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_thing_tags").Add(1)
		mm.latency.With("method", "update_thing_tags").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateThingTags(token, thing)
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

// ShareThing adds metrics middleware to share thing method.
func (mm *metricsMiddleware) ShareThing(token, thingID string, req sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "share_thing").Add(1)
		mm.latency.With("method", "share_thing").Observe(float64(time.Since(begin).Seconds()))
	}(time.Now())

	return mm.svc.ShareThing(token, thingID, req)
}

// UnshareThing adds metrics middleware to unshare thing method.
func (mm *metricsMiddleware) UnshareThing(token, thingID string, req sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "unshare_thing").Add(1)
		mm.latency.With("method", "unshare_thing").Observe(float64(time.Since(begin).Seconds()))
	}(time.Now())

	return mm.svc.UnshareThing(token, thingID, req)
}

// ListThingUsers adds metrics middleware to list thing users method.
func (mm *metricsMiddleware) ListThingUsers(token, thingID, relation string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_thing_users").Add(1)
		mm.latency.With("method", "list_thing_users").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListThingUsers(token, thingID, relation, page, limit)
}

// ListChannelsByThing adds metrics middleware to list channels by thing method.
func (mm *metricsMiddleware) ListChannelsByThing(token, thingID string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_channels_by_thing").Add(1)
		mm.latency.With("method", "list_channels_by_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListChannelsByThing(token, thingID, page, limit)
}

// CreateChannel adds metrics middleware to create channel method.
func (mm *metricsMiddleware) CreateChannel(channel sdk.Channel, token string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "create_channel").Add(1)
		mm.latency.With("method", "create_channel").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.CreateChannel(channel, token)
}

// CreateChannels adds metrics middleware to create channels method.
func (mm *metricsMiddleware) CreateChannels(token string, channels ...sdk.Channel) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "create_channels").Add(1)
		mm.latency.With("method", "create_channels").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.CreateChannels(token, channels...)
}

// ListChannels adds metrics middleware to list channels method.
func (mm *metricsMiddleware) ListChannels(token, status string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_channels").Add(1)
		mm.latency.With("method", "list_channels").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListChannels(token, status, page, limit)
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
func (mm *metricsMiddleware) UpdateChannel(token string, channel sdk.Channel) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_channel").Add(1)
		mm.latency.With("method", "update_channel").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateChannel(token, channel)
}

// ListThingsByChannel adds metrics middleware to list things by channel method.
func (mm *metricsMiddleware) ListThingsByChannel(token, channelID string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_things_by_channel").Add(1)
		mm.latency.With("method", "list_things_by_channel").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListThingsByChannel(token, channelID, page, limit)
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
func (mm *metricsMiddleware) Connect(token string, connIDs sdk.Connection) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "connect").Add(1)
		mm.latency.With("method", "connect").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Connect(token, connIDs)
}

// Disconnect adds metrics middleware to disconnect method.
func (mm *metricsMiddleware) Disconnect(token string, connIDs sdk.Connection) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "disconnect").Add(1)
		mm.latency.With("method", "disconnect").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Disconnect(token, connIDs)
}

// ConnectThing adds metrics middleware to connect thing method.
func (mm *metricsMiddleware) ConnectThing(thingID, chanID, token string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "connect_thing").Add(1)
		mm.latency.With("method", "connect_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ConnectThing(thingID, chanID, token)
}

// DisconnectThing adds metrics middleware to disconnect thing method.
func (mm *metricsMiddleware) DisconnectThing(thID, chID, token string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "disconnect_thing").Add(1)
		mm.latency.With("method", "disconnect_thing").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DisconnectThing(thID, chID, token)
}

// AddUserToChannel adds metrics middleware to add user to channel method.
func (mm *metricsMiddleware) AddUserToChannel(token, channelID string, req sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "add_user_to_channel").Add(1)
		mm.latency.With("method", "add_user_to_channel").Observe(float64(time.Since(begin).Seconds()))
	}(time.Now())

	return mm.svc.AddUserToChannel(token, channelID, req)
}

// RemoveUserFromChannel adds metrics middleware to remove user from channel method.
func (mm *metricsMiddleware) RemoveUserFromChannel(token, channelID string, req sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "remove_user_from_channel").Add(1)
		mm.latency.With("method", "remove_user_from_channel").Observe(float64(time.Since(begin).Seconds()))
	}(time.Now())

	return mm.svc.RemoveUserFromChannel(token, channelID, req)
}

// ListChannelUsers adds metrics middleware to list channel users method.
func (mm *metricsMiddleware) ListChannelUsers(token, channelID, relation string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_channel_users").Add(1)
		mm.latency.With("method", "list_channel_users").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListChannelUsers(token, channelID, relation, page, limit)
}

// AddUserGroupToChannel adds metrics middleware to add usergroup to channel method.
func (mm *metricsMiddleware) AddUserGroupToChannel(token, channelID string, req sdk.UserGroupsRequest) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "add_usergroup_to_channel").Add(1)
		mm.latency.With("method", "add_usergroup_to_channel").Observe(float64(time.Since(begin).Seconds()))
	}(time.Now())

	return mm.svc.AddUserGroupToChannel(token, channelID, req)
}

// RemoveUserGroupFromChannel adds metrics middleware to remove usergroup from channel method.
func (mm *metricsMiddleware) RemoveUserGroupFromChannel(token, channelID string, req sdk.UserGroupsRequest) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "remove_usergroup_from_channel").Add(1)
		mm.latency.With("method", "remove_usergroup_from_channel").Observe(float64(time.Since(begin).Seconds()))
	}(time.Now())

	return mm.svc.RemoveUserGroupFromChannel(token, channelID, req)
}

// ListChannelUserGroups adds metrics middleware to list channel usergroups method.
func (mm *metricsMiddleware) ListChannelUserGroups(token, channelID string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_channel_usergroups").Add(1)
		mm.latency.With("method", "list_channel_usergroups").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListChannelUserGroups(token, channelID, page, limit)
}

// CreateGroups adds metrics middleware to create groups method.
func (mm *metricsMiddleware) CreateGroups(token string, groups ...sdk.Group) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "create_groups").Add(1)
		mm.latency.With("method", "create_groups").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.CreateGroups(token, groups...)
}

// ListGroupUsers adds metrics middleware to list group users method.
func (mm *metricsMiddleware) ListGroupUsers(token, id, relation string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_group_users").Add(1)
		mm.latency.With("method", "list_group_users").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListGroupUsers(token, id, relation, page, limit)
}

// Assign adds metrics middleware to assign method.
func (mm *metricsMiddleware) Assign(token, groupID string, userRelation sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "assign").Add(1)
		mm.latency.With("method", "assign").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Assign(token, groupID, userRelation)
}

// Unassign adds metrics middleware to unassign method.
func (mm *metricsMiddleware) Unassign(token, groupID string, userRelation sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "unassign").Add(1)
		mm.latency.With("method", "unassign").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Unassign(token, groupID, userRelation)
}

// ViewGroup adds metrics middleware to view group method.
func (mm *metricsMiddleware) ViewGroup(token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "view_group").Add(1)
		mm.latency.With("method", "view_group").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ViewGroup(token, id)
}

// UpdateGroup adds metrics middleware to update group method.
func (mm *metricsMiddleware) UpdateGroup(token string, group sdk.Group) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_group").Add(1)
		mm.latency.With("method", "update_group").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateGroup(token, group)
}

// ListGroups adds metrics middleware to list groups method.
func (mm *metricsMiddleware) ListGroups(token, status string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_groups").Add(1)
		mm.latency.With("method", "list_groups").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListGroups(token, status, page, limit)
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

// ListUSerGroupChannels adds metrics middleware to list usergroup channels method.
func (mm *metricsMiddleware) ListUserGroupChannels(token, userID string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_usergroup_channels").Add(1)
		mm.latency.With("method", "list_usergroup_channels").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListUserGroupChannels(token, userID, page, limit)
}

// Publish adds metrics middleware to publish method.
func (mm *metricsMiddleware) Publish(token, chID, thKey, baseUnit, name, unit string, baseTime, value float64) error {
	defer func(begin time.Time) {
		mm.counter.With("method", "publish").Add(1)
		mm.latency.With("method", "publish").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Publish(token, chID, thKey, baseUnit, name, unit, baseTime, value)
}

// ReadMessages adds metrics middleware to read messages method.
func (mm *metricsMiddleware) ReadMessages(token, chID, thKey string, page, limit uint64) ([]byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "read_messages").Add(1)
		mm.latency.With("method", "read_messages").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ReadMessages(token, chID, thKey, page, limit)
}

// CreateBootstrap adds metrics middleware to create bootstrap method.
func (mm *metricsMiddleware) CreateBootstrap(token string, config ...sdk.BootstrapConfig) error {
	defer func(begin time.Time) {
		mm.counter.With("method", "create_bootstrap").Add(1)
		mm.latency.With("method", "create_bootstrap").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.CreateBootstrap(token, config...)
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

// UpdateBootstrapConnections adds metrics middleware to  update bootstrap connections method.
func (mm *metricsMiddleware) UpdateBootstrapConnections(token string, config sdk.BootstrapConfig) error {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_bootstrap_connections").Add(1)
		mm.latency.With("method", "update_bootstrap_connections").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateBootstrapConnections(token, config)
}

// UpdateBootstrapCerts adds metrics middleware to update bootstrap certs method.
func (mm *metricsMiddleware) UpdateBootstrapCerts(token string, config sdk.BootstrapConfig) error {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_bootstrap_certs").Add(1)
		mm.latency.With("method", "update_bootstrap_certs").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateBootstrapCerts(token, config)
}

// DeleteBootstrap adds metrics middleware to delete bootstrap method.
func (mm *metricsMiddleware) DeleteBootstrap(token string, id string) error {
	defer func(begin time.Time) {
		mm.counter.With("method", "delete_bootstrap").Add(1)
		mm.latency.With("method", "delete_bootstrap").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DeleteBootstrap(token, id)
}

// UpdateBootstrapState adds metrics middleware to update bootstrap state method.
func (mm *metricsMiddleware) UpdateBootstrapState(token string, config sdk.BootstrapConfig) error {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_bootstrap_state").Add(1)
		mm.latency.With("method", "update_bootstrap_state").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateBootstrapState(token, config)
}

// ViewBootstrap adds metrics middleware to view bootstrap method.
func (mm *metricsMiddleware) ViewBootstrap(token string, id string) ([]byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "view_bootstrap").Add(1)
		mm.latency.With("method", "view_bootstrap").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ViewBootstrap(token, id)
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

// GetEntities adds metrics middleware to get entities method.
func (mm *metricsMiddleware) GetEntities(token, item, name, domainID, permission string, page, limit uint64) ([]byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "get_entities").Add(1)
		mm.latency.With("method", "get_entities").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.GetEntities(token, item, name, domainID, permission, page, limit)
}

// ErrorPage adds metrics middleware to error page method.
func (mm *metricsMiddleware) ErrorPage(errMsg string) ([]byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "errorpage").Add(1)
		mm.latency.With("method", "errorpage").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ErrorPage(errMsg)
}

// DomainLogin adds metrics middleware to domain login method.
func (mm *metricsMiddleware) DomainLogin(login sdk.Login, refreshToken string) (sdk.Token, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "domain_login").Add(1)
		mm.latency.With("method", "domain_login").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DomainLogin(login, refreshToken)
}

// ListDomains adds metrics middleware to list domains method.
func (mm *metricsMiddleware) ListDomains(token, status string, page, limit uint64) ([]byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "list_domains").Add(1)
		mm.latency.With("method", "list_domains").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ListDomains(token, status, page, limit)
}

// CreateDomain adds metrics middleware to create domain method.
func (mm *metricsMiddleware) CreateDomain(token string, domain sdk.Domain) error {
	defer func(begin time.Time) {
		mm.counter.With("method", "create_domain").Add(1)
		mm.latency.With("method", "create_domain").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.CreateDomain(token, domain)
}

// UpdateDomain adds metrics middleware to update domain method.
func (mm *metricsMiddleware) UpdateDomain(token string, domain sdk.Domain) error {
	defer func(begin time.Time) {
		mm.counter.With("method", "update_domain").Add(1)
		mm.latency.With("method", "update_domain").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.UpdateDomain(token, domain)
}

// Domain adds metrics middleware to domain method.
func (mm *metricsMiddleware) Domain(token, domainID string) ([]byte, error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "domain").Add(1)
		mm.latency.With("method", "domain").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Domain(token, domainID)
}

// EnableDomain adds metrics middleware to enable domain method.
func (mm *metricsMiddleware) EnableDomain(token, domainID string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "enable_domain").Add(1)
		mm.latency.With("method", "enable_domain").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.EnableDomain(token, domainID)
}

// DisableDomain adds metrics middleware to disable domain method.
func (mm *metricsMiddleware) DisableDomain(token, domainID string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "disable_domain").Add(1)
		mm.latency.With("method", "disable_domain").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DisableDomain(token, domainID)
}

// AssignMember adds metrics middleware to assign member method.
func (mm *metricsMiddleware) AssignMember(token, domainID string, req sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "assign_member").Add(1)
		mm.latency.With("method", "assign_member").Observe(float64(time.Since(begin).Seconds()))
	}(time.Now())

	return mm.svc.AssignMember(token, domainID, req)
}

// UnassignMember adds metrics middleware to unassign member method.
func (mm *metricsMiddleware) UnassignMember(token, domainID string, req sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "unassign_member").Add(1)
		mm.latency.With("method", "unassign_member").Observe(float64(time.Since(begin).Seconds()))
	}(time.Now())

	return mm.svc.UnassignMember(token, domainID, req)
}

// ViewMember adds metrics middleware to view member method.
func (mm *metricsMiddleware) ViewMember(token, identity string) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "view_member").Add(1)
		mm.latency.With("method", "view_member").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.ViewMember(token, identity)
}

// Members adds metrics middleware to members method.
func (mm *metricsMiddleware) Members(token, domainID string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "members").Add(1)
		mm.latency.With("method", "members").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Members(token, domainID, page, limit)
}

// SendInvitation adds metrics middleware to send invitation method.
func (mm *metricsMiddleware) SendInvitation(token string, invitation sdk.Invitation) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "send_invitation").Add(1)
		mm.latency.With("method", "send_invitation").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.SendInvitation(token, invitation)
}

// Invitations adds metrics middleware to invitations method.
func (mm *metricsMiddleware) Invitations(token, domainID string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "invitations").Add(1)
		mm.latency.With("method", "invitations").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.Invitations(token, domainID, page, limit)
}

// AcceptInvitation adds metrics middleware to accept invitation method.
func (mm *metricsMiddleware) AcceptInvitation(token, domainID string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "accept_invitation").Add(1)
		mm.latency.With("method", "accept_invitation").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.AcceptInvitation(token, domainID)
}

// DeleteInvitation adds metrics middleware to delete invitation method.
func (mm *metricsMiddleware) DeleteInvitation(token, userID, domainID string) (err error) {
	defer func(begin time.Time) {
		mm.counter.With("method", "delete_invitation").Add(1)
		mm.latency.With("method", "delete_invitation").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mm.svc.DeleteInvitation(token, userID, domainID)
}
