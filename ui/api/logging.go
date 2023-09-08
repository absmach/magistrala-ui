// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

//go:build !test
// +build !test

package api

import (
	"context"
	"fmt"
	"time"

	"github.com/ultravioletrs/mainflux-ui/ui"

	log "github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/pkg/messaging"
	sdk "github.com/mainflux/mainflux/pkg/sdk/go"
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
func (lm *loggingMiddleware) Index(ctx context.Context, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method index took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Index(ctx, token)
}

// Login adds logging middleware to login method.
func (lm *loggingMiddleware) Login(ctx context.Context) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method login took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Login(ctx)
}

// PasswordResetRequest adds logging middleware to password reset request method.
func (lm *loggingMiddleware) PasswordResetRequest(ctx context.Context, email string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method password_reset_request  for email %s took %s to complete", email, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.PasswordResetRequest(ctx, email)
}

// PasswordReset adds logging middleware to password reset method.
func (lm *loggingMiddleware) PasswordReset(ctx context.Context, token, password, confPassword string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method password_reset for token %s took %s to complete", token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.PasswordReset(ctx, token, password, confPassword)
}

// ShowPasswordReset adds logging middleware to show password reset method.
func (lm *loggingMiddleware) ShowPasswordReset(ctx context.Context) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method show_password_reset took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ShowPasswordReset(ctx)
}

// PasswordUpdate adds logging middleware to password update method.
func (lm *loggingMiddleware) PasswordUpdate(ctx context.Context) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method password_update took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.PasswordUpdate(ctx)
}

// Toke adds logging middleware to token method.
func (lm *loggingMiddleware) Token(ctx context.Context, user sdk.User) (token sdk.Token, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method token took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Token(ctx, user)
}

// RefreshToken adds logging middleware to refresh token method.
func (lm *loggingMiddleware) RefreshToken(ctx context.Context, refreshToken string) (token sdk.Token, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method refresh_token took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.RefreshToken(ctx, refreshToken)
}

// Logout adds logging middleware to logout method.
func (lm *loggingMiddleware) Logout(ctx context.Context) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method logout took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Logout(ctx)
}

// UserProfile adds logging middleware to user profile method.
func (lm *loggingMiddleware) UserProfile(ctx context.Context, token string) (user sdk.User, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method user_profile took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UserProfile(ctx, token)
}

// UpdatePassword adds logging middleware to update password method.
func (lm *loggingMiddleware) UpdatePassword(ctx context.Context, token, oldPass, newPass string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_password for token %s took %s to complete", token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdatePassword(ctx, token, oldPass, newPass)
}

// CreateUsers adds logging middleware to create users method.
func (lm *loggingMiddleware) CreateUsers(ctx context.Context, token string, user ...sdk.User) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method create_users took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.CreateUsers(ctx, token, user...)
}

// ListUsers adds logging middleware to list users method.
func (lm *loggingMiddleware) ListUsers(ctx context.Context, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_users took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListUsers(ctx, token)
}

// ViewUser adds logging middleware to view user method.
func (lm *loggingMiddleware) ViewUser(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method view_user for token %s and user %s took %s to complete", token, id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ViewUser(ctx, token, id)
}

// UpdateUser adds logging middleware to update user method.
func (lm *loggingMiddleware) UpdateUser(ctx context.Context, token, id string, user sdk.User) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_user for token %s and user %s took %s to complete", token, user.ID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateUser(ctx, token, id, user)
}

// UpdateUserTags adds logging middleware to update user tags method.
func (lm *loggingMiddleware) UpdateUserTags(ctx context.Context, token, id string, user sdk.User) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_user_tags for token %s and user %s took %s to complete", token, user.ID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateUserTags(ctx, token, id, user)
}

// UpdateUserIdentity adds logging middleware to update user identity method.
func (lm *loggingMiddleware) UpdateUserIdentity(ctx context.Context, token, id string, user sdk.User) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_user_identity for token %s and user %s took %s to complete", token, id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateUserIdentity(ctx, token, id, user)
}

// UpdateUserOwner adds logging middleware to update user owner method.
func (lm *loggingMiddleware) UpdateUserOwner(ctx context.Context, token, id string, user sdk.User) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_user_owner for token %s and user %s took %s to complete", token, id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateUserOwner(ctx, token, id, user)
}

// EnableUser adds logging middleware to enable user method.
func (lm *loggingMiddleware) EnableUser(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method enable_user for token %s and user %s took %s to complete", token, id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.EnableUser(ctx, token, id)
}

// DisableUser adds logging middleware to disable user method.
func (lm *loggingMiddleware) DisableUser(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method disable_user for token %s and user %s took %s to complete", token, id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.DisableUser(ctx, token, id)
}

// CreateThings adds logging middleware to create things method.
func (lm *loggingMiddleware) CreateThings(ctx context.Context, token string, things ...sdk.Thing) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method create_things took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.CreateThings(ctx, token, things...)
}

// ListThings adds logging middleware to list things method.
func (lm *loggingMiddleware) ListThings(ctx context.Context, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_things took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListThings(ctx, token)
}

// ViewThing adds logging middleware to view thing method.
func (lm *loggingMiddleware) ViewThing(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method view_thing for token %s and thing %s took %s to complete", token, id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ViewThing(ctx, token, id)
}

// UpdateThing adds logging middleware to update thing method.
func (lm *loggingMiddleware) UpdateThing(ctx context.Context, token, id string, thing sdk.Thing) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_thing for token %s and thing %s took %s to complete", token, thing.ID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateThing(ctx, token, id, thing)
}

// UpdateThingTags adds logging middleware to update thing tags method.
func (lm *loggingMiddleware) UpdateThingTags(ctx context.Context, token, id string, thing sdk.Thing) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_thing_tags for token %s and thing %s took %s to complete", token, thing.ID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateThingTags(ctx, token, id, thing)
}

// UpdateThingSecret adds logging middleware to update thing secret method.
func (lm *loggingMiddleware) UpdateThingSecret(ctx context.Context, token, id, secret string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_thing_secret for token %s and thing %s took %s to complete", token, id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateThingSecret(ctx, token, id, secret)
}

// EnableThing adds logging middleware to enable thing method.
func (lm *loggingMiddleware) EnableThing(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method enable_thing for token %s and thing %s took %s to complete", token, id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.EnableThing(ctx, token, id)
}

// DisableThing adds logging middleware to disable thing method.
func (lm *loggingMiddleware) DisableThing(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method disable_thing for token %s and thing %s took %s to complete", token, id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.DisableThing(ctx, token, id)
}

// UpdateThingOwner adds logging middleware to update thing owner method.
func (lm *loggingMiddleware) UpdateThingOwner(ctx context.Context, token, id string, thing sdk.Thing) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_thing_owner for token %s and thing %s took %s to complete", token, thing.ID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateThingOwner(ctx, token, id, thing)
}

// CreateChannels adds logging middleware to create channels method.
func (lm *loggingMiddleware) CreateChannels(ctx context.Context, token string, channels ...sdk.Channel) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method create_channels took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.CreateChannels(ctx, token, channels...)
}

// ViewChannel adds logging middleware to view channel method.
func (lm *loggingMiddleware) ViewChannel(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method view_channel for token %s and channel %s took %s to complete", token, id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ViewChannel(ctx, token, id)
}

// UpdateChannel adds logging middleware to update channel method.
func (lm *loggingMiddleware) UpdateChannel(ctx context.Context, token, id string, channel sdk.Channel) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_channel for token %s and channel %s took %s to complete", token, channel.ID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateChannel(ctx, token, id, channel)
}

// ListChannels adds logging middleware to list channels method.
func (lm *loggingMiddleware) ListChannels(ctx context.Context, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_channels took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListChannels(ctx, token)
}

// EnableChannel adds logging middleware to enable channel method.
func (lm *loggingMiddleware) EnableChannel(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method enable_channel for token %s and channel %s took %s to complete", token, id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.EnableChannel(ctx, token, id)
}

// DisableChannel adds logging middleware to disable channel method.
func (lm *loggingMiddleware) DisableChannel(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method disable_channel for token %s and channel %s took %s to complete", token, id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.DisableChannel(ctx, token, id)
}

// Connect adds logging middleware to connect method.
func (lm *loggingMiddleware) Connect(ctx context.Context, token string, connIDs sdk.ConnectionIDs) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method connect for token %s took %s to complete", token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Connect(ctx, token, connIDs)
}

// Disconnect adds logging middleware to disconnect method.
func (lm *loggingMiddleware) Disconnect(ctx context.Context, token string, connIDs sdk.ConnectionIDs) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method disconnect for token %s took %s to complete", token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Disconnect(ctx, token, connIDs)
}

// ListThingsByChannel adds logging middleware to list things by channel method.
func (lm *loggingMiddleware) ListThingsByChannel(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_things_by_channel for token %s and channel %s took %s to complete", token, id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListThingsByChannel(ctx, token, id)
}

// ListChannelsByThing adds logging middleware to list channels by thing method.
func (lm *loggingMiddleware) ListChannelsByThing(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_channels_by_thing for token %s and thing %s took %s to complete", token, id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListChannelsByThing(ctx, token, id)
}

// ConnectThing adds logging middleware to connect thing method.
func (lm *loggingMiddleware) ConnectThing(ctx context.Context, token string, connIDs sdk.ConnectionIDs) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method connect_thing for token %s, channel %v and thing %v took %s to complete", token, connIDs.ChannelIDs[0], connIDs.ThingIDs[0], time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ConnectThing(ctx, token, connIDs)
}

// ShareThing adds logging middleware to share thing method.
func (lm *loggingMiddleware) ShareThing(ctx context.Context, token, chanID, userID string, actions []string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method share_thing for token %s, channel %v and user %v took %s to complete", token, chanID, userID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ShareThing(ctx, token, chanID, userID, actions)
}

// DisconnectThing adds logging middleware to disconnect thing method.
func (lm *loggingMiddleware) DisconnectThing(ctx context.Context, thID, chID, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method disconnect_thing for token %s, channel %v and thing %v took %s to complete", token, chID, thID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.DisconnectThing(ctx, thID, chID, token)
}

// ConnectChannel adds logging middleware to connect channel method.
func (lm *loggingMiddleware) ConnectChannel(ctx context.Context, token string, connIDs sdk.ConnectionIDs) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method connect_channel for token %s, channel %v and thing %v took %s to complete", token, connIDs.ChannelIDs[0], connIDs.ThingIDs[0], time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ConnectChannel(ctx, token, connIDs)
}

// DisconnectChannel adds logging middleware to disconnect channel method.
func (lm *loggingMiddleware) DisconnectChannel(ctx context.Context, thID, chID, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method disconnect_channel for token %s, channel %v and thing %v took %s to complete", token, chID, thID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.DisconnectChannel(ctx, thID, chID, token)
}

// ListThingsPolicies adds logging middleware to list things polices method.
func (lm *loggingMiddleware) ListThingsPolicies(ctx context.Context, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_things_policies for token %s took %s to complete", token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListThingsPolicies(ctx, token)
}

// AddThingsPolicy adds logging middleware to add things policy method.
func (lm *loggingMiddleware) AddThingsPolicy(ctx context.Context, token string, policy sdk.Policy) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method add_things_policy for token %s took %s to complete", token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.AddThingsPolicy(ctx, token, policy)
}

// DeleteThingsPolicy adds logging middleware to delete things policy method.
func (lm *loggingMiddleware) DeleteThingsPolicy(ctx context.Context, token string, policy sdk.Policy) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method delete_things_policy for token %s took %s to complete", token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.DeleteThingsPolicy(ctx, token, policy)
}

// UpdateThingsPolicy adds logging middleware to update things policy method.
func (lm *loggingMiddleware) UpdateThingsPolicy(ctx context.Context, token string, policy sdk.Policy) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_things_policy for token %s took %s to complete", token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateThingsPolicy(ctx, token, policy)
}

// CreateGroups adds logging middleware to create groups method.
func (lm *loggingMiddleware) CreateGroups(ctx context.Context, token string, groups ...sdk.Group) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method create_groups took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.CreateGroups(ctx, token, groups...)
}

// ListGroups adds logging middleware to list groups method.
func (lm *loggingMiddleware) ListGroups(ctx context.Context, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_groups took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListGroups(ctx, token)
}

// ViewGroup adds logging middleware to view group method.
func (lm *loggingMiddleware) ViewGroup(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method view_group for token %s and group %s took %s to complete", token, id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ViewGroup(ctx, token, id)
}

// Assign adds logging middleware to assign method.
func (lm *loggingMiddleware) Assign(ctx context.Context, token, groupID, memberID string, memberType []string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method assign for token %s and member %s group id %s took %s to complete", token, memberID, groupID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Assign(ctx, token, groupID, memberID, memberType)
}

// Unassign adds logging middleware to unassign method.
func (lm *loggingMiddleware) Unassign(ctx context.Context, token, groupID, memberID string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method unassign for token %s and member %s group id %s took %s to complete", token, memberID, groupID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Unassign(ctx, token, groupID, memberID)
}

// UpdateGroup adds logging middleware to update group method.
func (lm *loggingMiddleware) UpdateGroup(ctx context.Context, token, id string, group sdk.Group) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_group for token %s and group %s took %s to complete", token, group.ID, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateGroup(ctx, token, id, group)
}

// ListGroupMembers adds logging middleware to list group members method.
func (lm *loggingMiddleware) ListGroupMembers(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_group_members for token %s and connections %s took %s to complete", token, id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListGroupMembers(ctx, token, id)
}

// EnableGroup adds logging middleware to enable group method.
func (lm *loggingMiddleware) EnableGroup(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method enable_group for token %s and group %s took %s to complete", token, id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.EnableGroup(ctx, token, id)
}

// DisableGroup adds logging middleware to disable group method.
func (lm *loggingMiddleware) DisableGroup(ctx context.Context, token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method disable_group for token %s and group %s took %s to complete", token, id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.DisableGroup(ctx, token, id)
}

// AddPolicy adds logging middleware to add policy method.
func (lm *loggingMiddleware) AddPolicy(ctx context.Context, token string, policy sdk.Policy) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method add_policy for token %s took %s to complete", token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.AddPolicy(ctx, token, policy)
}

// ListPolicies adds logging middleware to list policies method.
func (lm *loggingMiddleware) ListPolicies(ctx context.Context, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_policies for token %s took %s to complete", token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListPolicies(ctx, token)
}

// UpdatePolicy adds logging middleware to update policy method.
func (lm *loggingMiddleware) UpdatePolicy(ctx context.Context, token string, policy sdk.Policy) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_policy for token %s took %s to complete", token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdatePolicy(ctx, token, policy)
}

// DeletePolicy adds logging middleware to delete policy method.
func (lm *loggingMiddleware) DeletePolicy(ctx context.Context, token string, policy sdk.Policy) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method delete_policy for token %s took %s to complete", token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.DeletePolicy(ctx, token, policy)
}

// Publish adds logging middleware to publish method.
func (lm *loggingMiddleware) Publish(ctx context.Context, token, thKey string, msg *messaging.Message) (b []byte, err error) {
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

	return lm.svc.Publish(ctx, token, thKey, msg)
}

// ReadMessage adds logging middleware to read message method.
func (lm *loggingMiddleware) ReadMessage(ctx context.Context, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method read_message took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ReadMessage(ctx, token)
}

// WsConnection adds logging middleware to ws_connection method.
func (lm *loggingMiddleware) WsConnection(ctx context.Context, token, chID, thKey string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method ws_connection took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.WsConnection(ctx, token, chID, thKey)
}

// ListDeletedClients adds logging middleware to list deleted clients method.
func (lm *loggingMiddleware) ListDeletedClients(ctx context.Context, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_deleted_clients took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListDeletedClients(ctx, token)
}

// GetRemoteTerminal adds logging middleware to remote terminal.
func (lm *loggingMiddleware) GetRemoteTerminal(ctx context.Context, id string) (res []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method remote_terminal with id %s took %s to complete", id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.GetRemoteTerminal(ctx, id)
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

// CreateBootstrap adds logging middleware to create bootstrap method.
func (lm *loggingMiddleware) CreateBootstrap(ctx context.Context, token string, config ...sdk.BootstrapConfig) (data []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method create_bootstrap took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.CreateBootstrap(ctx, token, config...)
}

// DeleteBootstrap adds logging middleware to delete bootstrap method.
func (lm *loggingMiddleware) DeleteBootstrap(ctx context.Context, token string, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method delete_bootstrap took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.DeleteBootstrap(ctx, token, id)
}

// ListBootstrap adds logging middleware to list bootstrap method.
func (lm *loggingMiddleware) ListBootstrap(ctx context.Context, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_bootstrap took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListBootstrap(ctx, token)
}

// UpdateBootstrap adds logging middleware to update bootstrap method.
func (lm *loggingMiddleware) UpdateBootstrap(ctx context.Context, token string, config sdk.BootstrapConfig) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_bootstrap took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateBootstrap(ctx, token, config)
}

// UpdateBootstrapCerts adds logging middleware to update bootstrap certs method.
func (lm *loggingMiddleware) UpdateBootstrapCerts(ctx context.Context, token string, config sdk.BootstrapConfig) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_bootstrap_certs took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateBootstrapCerts(ctx, token, config)
}

// UpdateBootstrapConnections adds logging middleware to update bootstrap connections method.
func (lm *loggingMiddleware) UpdateBootstrapConnections(ctx context.Context, token string, config sdk.BootstrapConfig) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_bootstrap_connections took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.UpdateBootstrapConnections(ctx, token, config)
}

// ViewBootstrap adds logging middleware to view bootstrap method.
func (lm *loggingMiddleware) ViewBootstrap(ctx context.Context, token string, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method view_bootstrap took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ViewBootstrap(ctx, token, id)
}
