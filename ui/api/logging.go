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

func (lm *loggingMiddleware) ListUsers(ctx context.Context, token, alertMessage string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_users took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListUsers(ctx, token, alertMessage)
}

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

func (lm *loggingMiddleware) ListThings(ctx context.Context, token, alertMessage string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_things took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListThings(ctx, token, alertMessage)
}

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

func (lm *loggingMiddleware) ListChannels(ctx context.Context, token, alertMessage string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_channels took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListChannels(ctx, token, alertMessage)
}

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

func (lm *loggingMiddleware) ListGroups(ctx context.Context, token, alertMessage string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_groups took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ListGroups(ctx, token, alertMessage)
}

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

func (lm *loggingMiddleware) ReadMessage(ctx context.Context, token string) (b []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method Read_message took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.ReadMessage(ctx, token)
}

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
