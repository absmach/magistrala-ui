// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"time"

	"github.com/absmach/magistrala-ui/ui"
	log "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/messaging"
	sdk "github.com/absmach/magistrala/pkg/sdk/go"
)

var _ ui.Service = (*loggingMiddleware)(nil)

type loggingMiddleware struct {
	logger log.Logger
	svc    ui.Service
}

// LoggingMiddleware adds logging facilities to the adapter.
func LoggingMiddleware(svc ui.Service, logger log.Logger) ui.Service {
	return &loggingMiddleware{logger, svc}
}

// Index adds logging middleware to index method.
func (lm *loggingMiddleware) Index(token, orgID string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method index took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Index(token, orgID)
}

// Login adds logging middleware to login method.
func (lm *loggingMiddleware) Login() (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method login took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Login()
}

// Logout adds logging middleware to logout method.
func (lm *loggingMiddleware) Logout() (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method logout took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Logout()
}

// PasswordResetRequest adds logging middleware to password reset request method.
func (lm *loggingMiddleware) PasswordResetRequest(email string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method password_reset_request  for email %s took %s to complete", email, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.PasswordResetRequest(email)
}

// PasswordReset adds logging middleware to password reset method.
func (lm *loggingMiddleware) PasswordReset(token, password, confPassword string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method password_reset took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.PasswordReset(token, password, confPassword)
}

// ShowPasswordReset adds logging middleware to show password reset method.
func (lm *loggingMiddleware) ShowPasswordReset() (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method show_password_reset took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ShowPasswordReset()
}

// PasswordUpdate adds logging middleware to password update method.
func (lm *loggingMiddleware) PasswordUpdate(token string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method password_update took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.PasswordUpdate(token)
}

// UpdatePassword adds logging middleware to update password method.
func (lm *loggingMiddleware) UpdatePassword(token, oldPass, newPass string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_password took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdatePassword(token, oldPass, newPass)
}

// Toke adds logging middleware to token method.
func (lm *loggingMiddleware) Token(login sdk.Login) (token sdk.Token, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method token took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Token(login)
}

// RefreshToken adds logging middleware to refresh token method.
func (lm *loggingMiddleware) RefreshToken(refreshToken string) (token sdk.Token, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method refresh_token took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.RefreshToken(refreshToken)
}

// UserProfile adds logging middleware to user profile method.
func (lm *loggingMiddleware) UserProfile(token string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method user_profile took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UserProfile(token, page, limit)
}

// CreateUsers adds logging middleware to create users method.
func (lm *loggingMiddleware) CreateUsers(token string, users ...sdk.User) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method create_users took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.CreateUsers(token, users...)
}

// ListUsers adds logging middleware to list users method.
func (lm *loggingMiddleware) ListUsers(token string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_users took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListUsers(token, page, limit)
}

// ViewUser adds logging middleware to view user method.
func (lm *loggingMiddleware) ViewUser(token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method view_user for user %s took %s to complete", id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ViewUser(token, id)
}

// UpdateUser adds logging middleware to update user method.
func (lm *loggingMiddleware) UpdateUser(token, id string, user sdk.User) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_user for user %s took %s to complete", user.ID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateUser(token, id, user)
}

// UpdateUserTags adds logging middleware to update user tags method.
func (lm *loggingMiddleware) UpdateUserTags(token, id string, user sdk.User) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_user_tags for user %s took %s to complete", user.ID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateUserTags(token, id, user)
}

// UpdateUserIdentity adds logging middleware to update user identity method.
func (lm *loggingMiddleware) UpdateUserIdentity(token, id string, user sdk.User) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_user_identity for user %s took %s to complete", id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateUserIdentity(token, id, user)
}

// UpdateUserOwner adds logging middleware to update user owner method.
func (lm *loggingMiddleware) UpdateUserOwner(token, id string, user sdk.User) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_user_owner for user %s took %s to complete", id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateUserOwner(token, id, user)
}

// EnableUser adds logging middleware to enable user method.
func (lm *loggingMiddleware) EnableUser(token, id string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method enable_user for user %s took %s to complete", id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.EnableUser(token, id)
}

// DisableUser adds logging middleware to disable user method.
func (lm *loggingMiddleware) DisableUser(token, id string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method disable_user for user %s took %s to complete", id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.DisableUser(token, id)
}

// CreateThing adds logging middleware to create thing method.
func (lm *loggingMiddleware) CreateThing(thing sdk.Thing, token string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method create_thing took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.CreateThing(thing, token)
}

// CreateThings adds logging middleware to create things method.
func (lm *loggingMiddleware) CreateThings(token string, things ...sdk.Thing) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method create_things took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.CreateThings(token, things...)
}

// ListThings adds logging middleware to list things method.
func (lm *loggingMiddleware) ListThings(token string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_things took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListThings(token, page, limit)
}

// ViewThing adds logging middleware to view thing method.
func (lm *loggingMiddleware) ViewThing(token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method view_thing for thing %s took %s to complete", id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ViewThing(token, id)
}

// UpdateThing adds logging middleware to update thing method.
func (lm *loggingMiddleware) UpdateThing(token, id string, thing sdk.Thing) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_thing for thing %s took %s to complete", thing.ID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateThing(token, id, thing)
}

// UpdateThingTags adds logging middleware to update thing tags method.
func (lm *loggingMiddleware) UpdateThingTags(token, id string, thing sdk.Thing) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_thing_tags for thing %s took %s to complete", thing.ID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateThingTags(token, id, thing)
}

// UpdateThingSecret adds logging middleware to update thing secret method.
func (lm *loggingMiddleware) UpdateThingSecret(token, id, secret string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_thing_secret for thing %s took %s to complete", id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateThingSecret(token, id, secret)
}

// EnableThing adds logging middleware to enable thing method.
func (lm *loggingMiddleware) EnableThing(token, id string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method enable_thing for thing %s took %s to complete", id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.EnableThing(token, id)
}

// DisableThing adds logging middleware to disable thing method.
func (lm *loggingMiddleware) DisableThing(token, id string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method disable_thing for thing %s took %s to complete", id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.DisableThing(token, id)
}

// ShareThing adds logging middleware to share thing method.
func (lm *loggingMiddleware) ShareThing(token, thingID string, req sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method share_thing for thing %s took %s to complete", thingID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ShareThing(token, thingID, req)
}

// UnshareThing adds logging middleware to unshare thing method.
func (lm *loggingMiddleware) UnshareThing(token, thingID string, req sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method unshare_thing for thing %s took %s to complete", thingID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UnshareThing(token, thingID, req)
}

// ListThingUsers adds logging middleware to list thing users method.
func (lm *loggingMiddleware) ListThingUsers(token, thingID, relation string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_thing_users took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListThingUsers(token, thingID, relation, page, limit)
}

// ListChannelsByThing adds logging middleware to list channels by thing method.
func (lm *loggingMiddleware) ListChannelsByThing(token, thingID string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_channels_by_thing for thing %s took %s to complete", thingID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListChannelsByThing(token, thingID, page, limit)
}

// CreateChannel adds logging middleware to create channel method.
func (lm *loggingMiddleware) CreateChannel(channel sdk.Channel, token string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method create_channel took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.CreateChannel(channel, token)
}

// CreateChannels adds logging middleware to create channels method.
func (lm *loggingMiddleware) CreateChannels(token string, channels ...sdk.Channel) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method create_channels took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.CreateChannels(token, channels...)
}

// ListChannels adds logging middleware to list channels method.
func (lm *loggingMiddleware) ListChannels(token string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_channels took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListChannels(token, page, limit)
}

// ViewChannel adds logging middleware to view channel method.
func (lm *loggingMiddleware) ViewChannel(token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method view_channel for channel %s took %s to complete", id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ViewChannel(token, id)
}

// UpdateChannel adds logging middleware to update channel method.
func (lm *loggingMiddleware) UpdateChannel(token, id string, channel sdk.Channel) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_channel for channel %s took %s to complete", channel.ID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateChannel(token, id, channel)
}

// ListThingsByChannel adds logging middleware to list things by channel method.
func (lm *loggingMiddleware) ListThingsByChannel(token, channeID string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_things_by_channel for channel %s took %s to complete", channeID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListThingsByChannel(token, channeID, page, limit)
}

// EnableChannel adds logging middleware to enable channel method.
func (lm *loggingMiddleware) EnableChannel(token, id string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method enable_channel for channel %s took %s to complete", id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.EnableChannel(token, id)
}

// DisableChannel adds logging middleware to disable channel method.
func (lm *loggingMiddleware) DisableChannel(token, id string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method disable_channel for channel %s took %s to complete", id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.DisableChannel(token, id)
}

// Connect adds logging middleware to connect method.
func (lm *loggingMiddleware) Connect(token string, connIDs sdk.Connection) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method connect for thing %s to channel %s took %s to complete", connIDs.ThingID, connIDs.ChannelID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Connect(token, connIDs)
}

// Disconnect adds logging middleware to disconnect method.
func (lm *loggingMiddleware) Disconnect(token string, connIDs sdk.Connection) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method disconnect for thing %s to channel %s took %s to complete", connIDs.ThingID, connIDs.ChannelID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Disconnect(token, connIDs)
}

// ConnectThing adds logging middleware to connect thing method.
func (lm *loggingMiddleware) ConnectThing(thingID, chanID, token string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method connect_thing for thing %s to channel %s took %s to complete", thingID, chanID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ConnectThing(thingID, chanID, token)
}

// DisconnectThing adds logging middleware to disconnect thing method.
func (lm *loggingMiddleware) DisconnectThing(thID, chID, token string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method disconnect_thing for thing %s to channel %s took %s to complete", thID, chID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.DisconnectThing(thID, chID, token)
}

// AddUserToChannel adds logging middleware to add user to channel method.
func (lm *loggingMiddleware) AddUserToChannel(token, channelID string, req sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method add_user_to_channel for channel %s took %s to complete", channelID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.AddUserToChannel(token, channelID, req)
}

// RemoveUserFromChannel adds logging middleware to remove user from channel method.
func (lm *loggingMiddleware) RemoveUserFromChannel(token, channelID string, req sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method remove_user_from_channel for channel %s took %s to complete", channelID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.RemoveUserFromChannel(token, channelID, req)
}

// ListChannelUsers adds logging middleware to list channel users method.
func (lm *loggingMiddleware) ListChannelUsers(token, channelID, relation string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_channel_users took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListChannelUsers(token, channelID, relation, page, limit)
}

// AddUserGroupToChannel adds logging middleware to add usergroup to channel method.
func (lm *loggingMiddleware) AddUserGroupToChannel(token, channelID string, req sdk.UserGroupsRequest) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method add_usergroup_to_channel for channel %s took %s to complete", channelID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.AddUserGroupToChannel(token, channelID, req)
}

// RemoveUserGroupFromChannel adds logging middleware to remove usergroup from channel method.
func (lm *loggingMiddleware) RemoveUserGroupFromChannel(token, channelID string, req sdk.UserGroupsRequest) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method remove_usergroup_from_channel for channel %s took %s to complete", channelID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.RemoveUserGroupFromChannel(token, channelID, req)
}

// ListChannelUserGroups adds logging middleware to list channel user groups method.
func (lm *loggingMiddleware) ListChannelUserGroups(token, channelID string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_channel_usergroups took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListChannelUserGroups(token, channelID, page, limit)
}

// CreateGroups adds logging middleware to create groups method.
func (lm *loggingMiddleware) CreateGroups(token string, groups ...sdk.Group) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method create_groups took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.CreateGroups(token, groups...)
}

// ListGroupUsers adds logging middleware to list group users method.
func (lm *loggingMiddleware) ListGroupUsers(token, id, relation string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_group_users for group %s took %s to complete", id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListGroupUsers(token, id, relation, page, limit)
}

// Assign adds logging middleware to assign method.
func (lm *loggingMiddleware) Assign(token, groupID string, userRelation sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method assign for user %s to group  %s took %s to complete", userRelation.UserIDs[0], groupID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Assign(token, groupID, userRelation)
}

// Unassign adds logging middleware to unassign method.
func (lm *loggingMiddleware) Unassign(token, groupID string, userRelation sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method unassign for user %s to group %s took %s to complete", userRelation.UserIDs[0], groupID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Unassign(token, groupID, userRelation)
}

// ViewGroup adds logging middleware to view group method.
func (lm *loggingMiddleware) ViewGroup(token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method view_group for group %s took %s to complete", id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ViewGroup(token, id)
}

// UpdateGroup adds logging middleware to update group method.
func (lm *loggingMiddleware) UpdateGroup(token, id string, group sdk.Group) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_group for group %s took %s to complete", group.ID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateGroup(token, id, group)
}

// ListGroups adds logging middleware to list groups method.
func (lm *loggingMiddleware) ListGroups(token string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_groups took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListGroups(token, page, limit)
}

// EnableGroup adds logging middleware to enable group method.
func (lm *loggingMiddleware) EnableGroup(token, id string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method enable_group for group %s took %s to complete", id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.EnableGroup(token, id)
}

// DisableGroup adds logging middleware to disable group method.
func (lm *loggingMiddleware) DisableGroup(token, id string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method disable_group for group %s took %s to complete", id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.DisableGroup(token, id)
}

// ListUserGroupChannels adds logging middleware to list usergroup channels method.
func (lm *loggingMiddleware) ListUserGroupChannels(token, groupID string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_usergroup_channels took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListUserGroupChannels(token, groupID, page, limit)
}

// Publish adds logging middleware to publish method.
func (lm *loggingMiddleware) Publish(token, thKey string, msg *messaging.Message) (err error) {
	defer func(begin time.Time) {
		destChannel := msg.Channel
		if msg.Subtopic != "" {
			destChannel = fmt.Sprintf("%s.%s", destChannel, msg.Subtopic)
		}
		message := fmt.Sprintf("Method publish to channel %s took %s to complete", destChannel, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Publish(token, thKey, msg)
}

// ReadMessage adds logging middleware to read message method.
func (lm *loggingMiddleware) ReadMessage(token, chID, thKey string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method read_message took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ReadMessage(token, chID, thKey, page, limit)
}

// CreateBootstrap adds logging middleware to create bootstrap method.
func (lm *loggingMiddleware) CreateBootstrap(token string, config ...sdk.BootstrapConfig) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method create_bootstrap took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.CreateBootstrap(token, config...)
}

// ListBootstrap adds logging middleware to list bootstrap method.
func (lm *loggingMiddleware) ListBootstrap(token string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_bootstrap took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListBootstrap(token, page, limit)
}

// UpdateBootstrap adds logging middleware to update bootstrap method.
func (lm *loggingMiddleware) UpdateBootstrap(token string, config sdk.BootstrapConfig) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_bootstrap took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateBootstrap(token, config)
}

// UpdateBootstrapConnections adds logging middleware to update bootstrap connections method.
func (lm *loggingMiddleware) UpdateBootstrapConnections(token string, config sdk.BootstrapConfig) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_bootstrap_connections took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateBootstrapConnections(token, config)
}

// UpdateBootstrapCerts adds logging middleware to update bootstrap certs method.
func (lm *loggingMiddleware) UpdateBootstrapCerts(token string, config sdk.BootstrapConfig) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_bootstrap_certs took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateBootstrapCerts(token, config)
}

// DeleteBootstrap adds logging middleware to delete bootstrap method.
func (lm *loggingMiddleware) DeleteBootstrap(token string, id string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method delete_bootstrap took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.DeleteBootstrap(token, id)
}

// ViewBootstrap adds logging middleware to view bootstrap method.
func (lm *loggingMiddleware) ViewBootstrap(token string, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method view_bootstrap took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ViewBootstrap(token, id)
}

// GetRemoteTerminal adds logging middleware to remote terminal.
func (lm *loggingMiddleware) GetRemoteTerminal(id, token string) (res []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method remote_terminal with id %s took %s to complete", id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.GetRemoteTerminal(id, token)
}

// ProcessTerminalCommand adds logging middleware to async function ProcessTerminalCommand.
func (lm *loggingMiddleware) ProcessTerminalCommand(ctx context.Context, id, token, command string, res chan string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method remote_terminal took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ProcessTerminalCommand(ctx, id, token, command, res)
}

// GetEntities adds logging middleware to get entities method.
func (lm *loggingMiddleware) GetEntities(token, item, name, orgID, permission string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method get_entities took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.GetEntities(token, item, name, orgID, permission, page, limit)
}

// ErrorPage adds logging middleware to error page method.
func (lm *loggingMiddleware) ErrorPage(errMsg string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method ErrorPage took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ErrorPage(errMsg)
}

// OrganizationLogin adds logging middleware to organization login method.
func (lm *loggingMiddleware) OrganizationLogin(login sdk.Login, refreshToken string) (token sdk.Token, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method organization_login took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}

		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.OrganizationLogin(login, refreshToken)
}

// ListOrganizations adds logging middleware to list organizations method.
func (lm *loggingMiddleware) ListOrganizations(token string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_organizations took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListOrganizations(token, page, limit)
}

// CreateOrganization adds logging middleware to create organization method.
func (lm *loggingMiddleware) CreateOrganization(token string, domain sdk.Domain) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method create_organization took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.CreateOrganization(token, domain)
}

// UpdateOrganization adds logging middleware to update organization method.
func (lm *loggingMiddleware) UpdateOrganization(token string, domain sdk.Domain) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_organization for organization %s took %s to complete", domain.ID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateOrganization(token, domain)
}

// Organization adds logging middleware to organization method.
func (lm *loggingMiddleware) Organization(token, orgID, tabActive string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method organization for organization %s took %s to complete", orgID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Organization(token, orgID, tabActive, page, limit)
}

// AssignMember adds logging middleware to assign member method.
func (lm *loggingMiddleware) AssignMember(token, orgID string, req sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method assign_member for organization %s took %s to complete", orgID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.AssignMember(token, orgID, req)
}

// UnassignMember adds logging middleware to unassign member method.
func (lm *loggingMiddleware) UnassignMember(token, orgID string, req sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method unassign_member for organization %s took %s to complete", orgID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UnassignMember(token, orgID, req)
}

// ViewMember adds logging middleware to view member method.
func (lm *loggingMiddleware) ViewMember(token, identity string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method view_member for member %s took %s to complete", identity, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ViewMember(token, identity)
}
