// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"log/slog"
	"time"

	"github.com/absmach/magistrala-ui/ui"
	sdk "github.com/absmach/magistrala/pkg/sdk/go"
)

var _ ui.Service = (*loggingMiddleware)(nil)

type loggingMiddleware struct {
	logger *slog.Logger
	svc    ui.Service
}

// LoggingMiddleware adds logging facilities to the adapter.
func LoggingMiddleware(svc ui.Service, logger *slog.Logger) ui.Service {
	return &loggingMiddleware{logger, svc}
}

// Index adds logging middleware to index method.
func (lm *loggingMiddleware) Index(token string) (b []byte, err error) {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		if err != nil {
			lm.logger.Warn("View index page failed to complete successfully", slog.Any("error", err), duration)
			return
		}
		lm.logger.Info("View index page completed successfully", duration)
	}(time.Now())

	return lm.svc.Index(token)
}

// ViewRegistration adds logging middleware to view registration method.
func (lm *loggingMiddleware) ViewRegistration() (b []byte, err error) {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		if err != nil {
			lm.logger.Warn("View registration page failed to complete successfully", slog.Any("error", err), duration)
			return
		}
		lm.logger.Info("View registration page completed successfully", duration)
	}(time.Now())

	return lm.svc.ViewRegistration()
}

// Register adds logging middleware to register method.
func (lm *loggingMiddleware) RegisterUser(user sdk.User) (t sdk.Token, err error) {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		if err != nil {
			lm.logger.Warn("Register user failed to complete successfully", slog.Any("error", err), duration)
			return
		}
		lm.logger.Info("Register user completed successfully", duration)
	}(time.Now())

	return lm.svc.RegisterUser(user)
}

// Login adds logging middleware to login method.
func (lm *loggingMiddleware) Login() (b []byte, err error) {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		if err != nil {
			lm.logger.Warn("View login page failed to complete successfully", slog.Any("error", err), duration)
			return
		}
		lm.logger.Info("View login page completed successfully", duration)
	}(time.Now())

	return lm.svc.Login()
}

// Logout adds logging middleware to logout method.
func (lm *loggingMiddleware) Logout() (err error) {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		if err != nil {
			lm.logger.Warn("Logout failed to complete successfully", slog.Any("error", err), duration)
			return
		}
		lm.logger.Info("Logout completed successfully", duration)
	}(time.Now())

	return lm.svc.Logout()
}

// KratosSignIn adds logging middleware to kratos signin method.
func (lm *loggingMiddleware) KratosSignIn() (url string, err error) {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		if err != nil {
			lm.logger.Warn("Kratos sign in failed to complete successfully", slog.Any("error", err), duration)
			return
		}
		lm.logger.Info("Kratos sign in completed successfully", duration)
	}(time.Now())

	return lm.svc.KratosSignIn()
}

// KratosSignUp adds logging middleware to kratos signup method.
func (lm *loggingMiddleware) KratosSignUp() (url string, err error) {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		if err != nil {
			lm.logger.Warn("Kratos sign up failed to complete successfully", slog.Any("error", err), duration)
			return
		}
		lm.logger.Info("Kratos sign up completed successfully", duration)
	}(time.Now())

	return lm.svc.KratosSignUp()
}

// PasswordResetRequest adds logging middleware to password reset request method.
func (lm *loggingMiddleware) PasswordResetRequest(email string) (err error) {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		if err != nil {
			lm.logger.Warn("Send password reset request failed to complete successfully", slog.Any("error", err), duration)
		}
		lm.logger.Info("Send password reset request completed successfully", duration)
	}(time.Now())

	return lm.svc.PasswordResetRequest(email)
}

// PasswordReset adds logging middleware to password reset method.
func (lm *loggingMiddleware) PasswordReset(token, password, confPassword string) (err error) {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		if err != nil {
			lm.logger.Warn("Password reset failed to complete successfully", slog.Any("error", err), duration)
		}
		lm.logger.Info("Password reset completed successfully", duration)
	}(time.Now())

	return lm.svc.PasswordReset(token, password, confPassword)
}

// ShowPasswordReset adds logging middleware to show password reset method.
func (lm *loggingMiddleware) ShowPasswordReset() (b []byte, err error) {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		if err != nil {
			lm.logger.Warn("View password reset page failed to complete successfully", slog.Any("error", err), duration)
		}
		lm.logger.Info("View password reset page completed successfully", duration)
	}(time.Now())

	return lm.svc.ShowPasswordReset()
}

// PasswordUpdate adds logging middleware to password update method.
func (lm *loggingMiddleware) PasswordUpdate() (b []byte, err error) {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		if err != nil {
			lm.logger.Warn("View password update page failed to complete successfully", slog.Any("error", err), duration)
			return
		}
		lm.logger.Info("View password update page completed successfully", duration)
	}(time.Now())

	return lm.svc.PasswordUpdate()
}

// UpdatePassword adds logging middleware to update password method.
func (lm *loggingMiddleware) UpdatePassword(token, oldPass, newPass string) (err error) {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		if err != nil {
			lm.logger.Warn("Password update failed to complete successfully", slog.Any("error", err), duration)
			return
		}
		lm.logger.Info("Password update completed successfully", duration)
	}(time.Now())

	return lm.svc.UpdatePassword(token, oldPass, newPass)
}

// Toke adds logging middleware to token method.
func (lm *loggingMiddleware) Token(login sdk.Login) (t sdk.Token, err error) {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		if err != nil {
			lm.logger.Warn("Token request failed to complete successfully", slog.Any("error", err), duration)
			return
		}
		lm.logger.Info("Token request completed successfully", duration)
	}(time.Now())

	return lm.svc.Token(login)
}

// RefreshToken adds logging middleware to refresh token method.
func (lm *loggingMiddleware) RefreshToken(refreshToken string) (token sdk.Token, err error) {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		if err != nil {
			lm.logger.Warn("Token refresh failed to complete successfully", slog.Any("error", err), duration)
			return
		}
		lm.logger.Info("Token refresh completed successfully", duration)
	}(time.Now())

	return lm.svc.RefreshToken(refreshToken)
}

// Session adds logging middleware to session details method.
func (lm *loggingMiddleware) Session(token, session, domainID string) (s string, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("domain_id", domainID),
			slog.String("session", session),
		}

		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Session failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Session completed successfully", args...)
	}(time.Now())

	return lm.svc.Session(token, session, domainID)
}

// CreateUsers adds logging middleware to create users method.
func (lm *loggingMiddleware) CreateUsers(token string, users ...sdk.User) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Any("no_of_users", len(users)),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Create users failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Create users completed successfully", args...)
	}(time.Now())

	return lm.svc.CreateUsers(token, users...)
}

// ListUsers adds logging middleware to list users method.
func (lm *loggingMiddleware) ListUsers(token, status string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("status", status),
			slog.Uint64("page", page),
			slog.Uint64("limit", limit),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("List users failed to complete successfully", args...)
			return
		}
		lm.logger.Info("List users completed successfully", args...)
	}(time.Now())

	return lm.svc.ListUsers(token, status, page, limit)
}

// ViewUser adds logging middleware to view user method.
func (lm *loggingMiddleware) ViewUser(token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("user_id", id),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("View user failed to complete successfully", args...)
			return
		}
		lm.logger.Info("View user completed successfully", args...)
	}(time.Now())

	return lm.svc.ViewUser(token, id)
}

// UpdateUser adds logging middleware to update user method.
func (lm *loggingMiddleware) UpdateUser(token string, user sdk.User) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("user", slog.String("id", user.ID), slog.String("name", user.Name), slog.Any("metadata", user.Metadata)),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Update user failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Update user completed successfully", args...)
	}(time.Now())

	return lm.svc.UpdateUser(token, user)
}

// UpdateUserTags adds logging middleware to update user tags method.
func (lm *loggingMiddleware) UpdateUserTags(token string, user sdk.User) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("user", slog.String("id", user.ID), slog.Any("tags", user.Tags)),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Update user tags failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Update user tags completed successfully", args...)
	}(time.Now())

	return lm.svc.UpdateUserTags(token, user)
}

// UpdateUserIdentity adds logging middleware to update user identity method.
func (lm *loggingMiddleware) UpdateUserIdentity(token string, user sdk.User) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("user_id", user.ID),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Update user identity failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Update user identity completed successfully", args...)
	}(time.Now())

	return lm.svc.UpdateUserIdentity(token, user)
}

// UpdateUserRole adds logging middleware to update user role method.
func (lm *loggingMiddleware) UpdateUserRole(token string, user sdk.User) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("user", slog.String("id", user.ID), slog.String("role", user.Role)),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Update user role failed to complete successfully", args...)
		}
		lm.logger.Info("Update user role completed successfully", args...)
	}(time.Now())

	return lm.svc.UpdateUserRole(token, user)
}

// EnableUser adds logging middleware to enable user method.
func (lm *loggingMiddleware) EnableUser(token, id string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("user_id", id),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Enable user failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Enable user completed successfully", args...)
	}(time.Now())

	return lm.svc.EnableUser(token, id)
}

// DisableUser adds logging middleware to disable user method.
func (lm *loggingMiddleware) DisableUser(token, id string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("user_id", id),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Disable user failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Disable user completed successfully", args...)
	}(time.Now())

	return lm.svc.DisableUser(token, id)
}

// CreateThing adds logging middleware to create thing method.
func (lm *loggingMiddleware) CreateThing(thing sdk.Thing, token string) (err error) {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		if err != nil {
			lm.logger.Warn("Create thing failed to complete successfully", slog.Any("error", err), duration)
			return
		}
		lm.logger.Info("Create thing completed successfully", duration)
	}(time.Now())

	return lm.svc.CreateThing(thing, token)
}

// CreateThings adds logging middleware to create things method.
func (lm *loggingMiddleware) CreateThings(token string, things ...sdk.Thing) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Any("no_of_things", len(things)),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Create things failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Create things completed successfully", args...)
	}(time.Now())

	return lm.svc.CreateThings(token, things...)
}

// ListThings adds logging middleware to list things method.
func (lm *loggingMiddleware) ListThings(token, status string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("status", status),
			slog.Uint64("page", page),
			slog.Uint64("limit", limit),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("List things failed to complete successfully", args...)
			return
		}
		lm.logger.Info("List things completed successfully", args...)
	}(time.Now())

	return lm.svc.ListThings(token, status, page, limit)
}

// ViewThing adds logging middleware to view thing method.
func (lm *loggingMiddleware) ViewThing(token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("thing_id", id),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("View thing failed to complete successfully", args...)
			return
		}
		lm.logger.Info("View thing completed successfully", args...)
	}(time.Now())

	return lm.svc.ViewThing(token, id)
}

// UpdateThing adds logging middleware to update thing method.
func (lm *loggingMiddleware) UpdateThing(token string, thing sdk.Thing) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("thing", slog.String("id", thing.ID), slog.String("name", thing.Name), slog.Any("metadata", thing.Metadata)),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Update thing failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Update thing completed successfully", args...)
	}(time.Now())

	return lm.svc.UpdateThing(token, thing)
}

// UpdateThingTags adds logging middleware to update thing tags method.
func (lm *loggingMiddleware) UpdateThingTags(token string, thing sdk.Thing) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("thing", slog.String("id", thing.ID), slog.Any("tags", thing.Tags)),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Update thing tags failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Update thing tags completed successfully", args...)
	}(time.Now())

	return lm.svc.UpdateThingTags(token, thing)
}

// UpdateThingSecret adds logging middleware to update thing secret method.
func (lm *loggingMiddleware) UpdateThingSecret(token, id, secret string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("thing_id", id),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Update thing secret failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Update thing secret completed successfully", args...)
	}(time.Now())

	return lm.svc.UpdateThingSecret(token, id, secret)
}

// EnableThing adds logging middleware to enable thing method.
func (lm *loggingMiddleware) EnableThing(token, id string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("thing_id", id),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Enable thing failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Enable thing completed successfully", args...)
	}(time.Now())

	return lm.svc.EnableThing(token, id)
}

// DisableThing adds logging middleware to disable thing method.
func (lm *loggingMiddleware) DisableThing(token, id string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("thing_id", id),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Disable thing failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Disable thing completed successfully", args...)
	}(time.Now())

	return lm.svc.DisableThing(token, id)
}

// ShareThing adds logging middleware to share thing method.
func (lm *loggingMiddleware) ShareThing(token, thingID string, req sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("thing_id", thingID),
			slog.Any("user_ids", req.UserIDs),
			slog.String("relation", req.Relation),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Share thing failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Share thing completed successfully", args...)
	}(time.Now())

	return lm.svc.ShareThing(token, thingID, req)
}

// UnshareThing adds logging middleware to unshare thing method.
func (lm *loggingMiddleware) UnshareThing(token, thingID string, req sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("thing_id", thingID),
			slog.Any("user_ids", req.UserIDs),
			slog.String("relation", req.Relation),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Unshare thing failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Unshare thing completed successfully", args...)
	}(time.Now())

	return lm.svc.UnshareThing(token, thingID, req)
}

// ListThingUsers adds logging middleware to list thing users method.
func (lm *loggingMiddleware) ListThingUsers(token, id, relation string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("thing_id", id),
			slog.String("relation", relation),
			slog.Uint64("page", page),
			slog.Uint64("limit", limit),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("List thing users failed to complete successfully", args...)
			return
		}
		lm.logger.Info("List thing users completed successfully", args...)
	}(time.Now())

	return lm.svc.ListThingUsers(token, id, relation, page, limit)
}

// ListChannelsByThing adds logging middleware to list channels by thing method.
func (lm *loggingMiddleware) ListChannelsByThing(token, id string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("thing_id", id),
			slog.Uint64("page", page),
			slog.Uint64("limit", limit),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("List channels by thing failed to complete successfully", args...)
			return
		}
		lm.logger.Info("List channels by thing completed successfully", args...)
	}(time.Now())

	return lm.svc.ListChannelsByThing(token, id, page, limit)
}

// CreateChannel adds logging middleware to create channel method.
func (lm *loggingMiddleware) CreateChannel(channel sdk.Channel, token string) (err error) {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		if err != nil {
			lm.logger.Warn("Create channel failed to complete successfully", slog.Any("error", err), duration)
			return
		}
		lm.logger.Info("Create channel completed successfully", duration)
	}(time.Now())

	return lm.svc.CreateChannel(channel, token)
}

// CreateChannels adds logging middleware to create channels method.
func (lm *loggingMiddleware) CreateChannels(token string, channels ...sdk.Channel) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Any("no_of_channels", len(channels)),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Create channels failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Create channels completed successfully", args...)
	}(time.Now())

	return lm.svc.CreateChannels(token, channels...)
}

// ListChannels adds logging middleware to list channels method.
func (lm *loggingMiddleware) ListChannels(token, status string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("status", status),
			slog.Uint64("page", page),
			slog.Uint64("limit", limit),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("List channels failed to complete successfully", args...)
			return
		}
		lm.logger.Info("List channels completed successfully", args...)
	}(time.Now())

	return lm.svc.ListChannels(token, status, page, limit)
}

// ViewChannel adds logging middleware to view channel method.
func (lm *loggingMiddleware) ViewChannel(token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("channel_id", id),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("View channel failed to complete successfully", args...)
			return
		}
		lm.logger.Info("View channel completed successfully", args...)
	}(time.Now())

	return lm.svc.ViewChannel(token, id)
}

// UpdateChannel adds logging middleware to update channel method.
func (lm *loggingMiddleware) UpdateChannel(token string, channel sdk.Channel) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("channel", slog.String("id", channel.ID), slog.String("name", channel.Name), slog.String("description", channel.Description), slog.Any("metadata", channel.Metadata)),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Update channel failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Update channel completed successfully", args...)
	}(time.Now())

	return lm.svc.UpdateChannel(token, channel)
}

// ListThingsByChannel adds logging middleware to list things by channel method.
func (lm *loggingMiddleware) ListThingsByChannel(token, id string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("channel_id", id),
			slog.Uint64("page", page),
			slog.Uint64("limit", limit),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("List things by channel failed to complete successfully", args...)
			return
		}
		lm.logger.Info("List things by channel completed successfully", args...)
	}(time.Now())

	return lm.svc.ListThingsByChannel(token, id, page, limit)
}

// EnableChannel adds logging middleware to enable channel method.
func (lm *loggingMiddleware) EnableChannel(token, id string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("channel_id", id),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Enable channel failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Enable channel completed successfully", args...)
	}(time.Now())

	return lm.svc.EnableChannel(token, id)
}

// DisableChannel adds logging middleware to disable channel method.
func (lm *loggingMiddleware) DisableChannel(token, id string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("channel_id", id),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Disable channel failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Disable channel completed successfully", args...)
	}(time.Now())

	return lm.svc.DisableChannel(token, id)
}

// Connect adds logging middleware to connect method.
func (lm *loggingMiddleware) Connect(token string, connIDs sdk.Connection) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("channel_id", connIDs.ChannelID),
			slog.String("thing_id", connIDs.ThingID),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Method connect failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Method connect completed successfully", args...)
	}(time.Now())

	return lm.svc.Connect(token, connIDs)
}

// Disconnect adds logging middleware to disconnect method.
func (lm *loggingMiddleware) Disconnect(token string, connIDs sdk.Connection) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("channel_id", connIDs.ChannelID),
			slog.String("thing_id", connIDs.ThingID),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Method disconnect failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Method disconnect completed successfully", args...)
	}(time.Now())

	return lm.svc.Disconnect(token, connIDs)
}

// ConnectThing adds logging middleware to connect thing method.
func (lm *loggingMiddleware) ConnectThing(thingID, channelID, token string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("channel_id", channelID),
			slog.String("thing_id", thingID),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Connect thing failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Connect thing completed successfully", args...)
	}(time.Now())

	return lm.svc.ConnectThing(thingID, channelID, token)
}

// DisconnectThing adds logging middleware to disconnect thing method.
func (lm *loggingMiddleware) DisconnectThing(thingID, channelID, token string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("channel_id", channelID),
			slog.String("thing_id", thingID),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Disconnect thing failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Disconnect thing completed successfully", args...)
	}(time.Now())

	return lm.svc.DisconnectThing(thingID, channelID, token)
}

// AddUserToChannel adds logging middleware to add user to channel method.
func (lm *loggingMiddleware) AddUserToChannel(token, channelID string, req sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("channel_id", channelID),
			slog.Any("user_ids", req.UserIDs),
			slog.String("relation", req.Relation),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Add user to channel failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Add user to channel completed successfully", args...)
	}(time.Now())

	return lm.svc.AddUserToChannel(token, channelID, req)
}

// RemoveUserFromChannel adds logging middleware to remove user from channel method.
func (lm *loggingMiddleware) RemoveUserFromChannel(token, channelID string, req sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("channel_id", channelID),
			slog.Any("user_ids", req.UserIDs),
			slog.String("relation", req.Relation),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Remove user from channel failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Remove user from channel completed successfully", args...)
	}(time.Now())

	return lm.svc.RemoveUserFromChannel(token, channelID, req)
}

// ListChannelUsers adds logging middleware to list channel users method.
func (lm *loggingMiddleware) ListChannelUsers(token, channelID, relation string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("channel_id", channelID),
			slog.String("relation", relation),
			slog.Uint64("page", page),
			slog.Uint64("limit", limit),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("List channel users failed to complete successfully", args...)
			return
		}
		lm.logger.Info("List channel users completed successfully", args...)
	}(time.Now())

	return lm.svc.ListChannelUsers(token, channelID, relation, page, limit)
}

// AddUserGroupToChannel adds logging middleware to add usergroup to channel method.
func (lm *loggingMiddleware) AddUserGroupToChannel(token, channelID string, req sdk.UserGroupsRequest) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("channel_id", channelID),
			slog.Any("group_ids", req.UserGroupIDs),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Add usergroup to channel failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Add usergroup to channel completed successfully", args...)
	}(time.Now())

	return lm.svc.AddUserGroupToChannel(token, channelID, req)
}

// RemoveUserGroupFromChannel adds logging middleware to remove usergroup from channel method.
func (lm *loggingMiddleware) RemoveUserGroupFromChannel(token, channelID string, req sdk.UserGroupsRequest) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("channel_id", channelID),
			slog.Any("group_ids", req.UserGroupIDs),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Remove usergroup from channel failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Remove usergroup from channel completed successfully", args...)
	}(time.Now())

	return lm.svc.RemoveUserGroupFromChannel(token, channelID, req)
}

// ListChannelUserGroups adds logging middleware to list channel user groups method.
func (lm *loggingMiddleware) ListChannelUserGroups(token, id string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("channel_id", id),
			slog.Uint64("page", page),
			slog.Uint64("limit", limit),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("List channel usergroups failed to complete successfully", args...)
			return
		}
		lm.logger.Info("List channel usergroups completed successfully", args...)
	}(time.Now())

	return lm.svc.ListChannelUserGroups(token, id, page, limit)
}

// CreateGroups adds logging middleware to create groups method.
func (lm *loggingMiddleware) CreateGroups(token string, groups ...sdk.Group) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Any("no_of_groups", len(groups)),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Create groups failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Create groups completed successfully", args...)
	}(time.Now())

	return lm.svc.CreateGroups(token, groups...)
}

// ListGroupUsers adds logging middleware to list group users method.
func (lm *loggingMiddleware) ListGroupUsers(token, id, relation string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("group_id", id),
			slog.String("relation", relation),
			slog.Uint64("page", page),
			slog.Uint64("limit", limit),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("List group users failed to complete successfully", args...)
			return
		}
		lm.logger.Info("List group users completed successfully", args...)
	}(time.Now())

	return lm.svc.ListGroupUsers(token, id, relation, page, limit)
}

// Assign adds logging middleware to assign method.
func (lm *loggingMiddleware) Assign(token, groupID string, userRelation sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("group_id", groupID),
			slog.Any("user_ids", userRelation.UserIDs),
			slog.String("relation", userRelation.Relation),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Assign user to group failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Assign user to group completed successfully", args...)
	}(time.Now())

	return lm.svc.Assign(token, groupID, userRelation)
}

// Unassign adds logging middleware to unassign method.
func (lm *loggingMiddleware) Unassign(token, groupID string, userRelation sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("group_id", groupID),
			slog.Any("user_ids", userRelation.UserIDs),
			slog.String("relation", userRelation.Relation),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Unassign user from group failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Unassign user from group completed successfully", args...)
	}(time.Now())

	return lm.svc.Unassign(token, groupID, userRelation)
}

// ViewGroup adds logging middleware to view group method.
func (lm *loggingMiddleware) ViewGroup(token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("group_id", id),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("View group failed to complete successfully", args...)
			return
		}
		lm.logger.Info("View group completed successfully", args...)
	}(time.Now())

	return lm.svc.ViewGroup(token, id)
}

// UpdateGroup adds logging middleware to update group method.
func (lm *loggingMiddleware) UpdateGroup(token string, group sdk.Group) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("group", slog.String("id", group.ID), slog.String("name", group.Name), slog.String("description", group.Description), slog.Any("metadata", group.Metadata)),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Update group failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Update group completed successfully", args...)
	}(time.Now())

	return lm.svc.UpdateGroup(token, group)
}

// ListGroups adds logging middleware to list groups method.
func (lm *loggingMiddleware) ListGroups(token, status string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("status", status),
			slog.Uint64("page", page),
			slog.Uint64("limit", limit),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("List groups failed to complete successfully", args...)
			return
		}
		lm.logger.Info("List groups completed successfully", args...)
	}(time.Now())

	return lm.svc.ListGroups(token, status, page, limit)
}

// EnableGroup adds logging middleware to enable group method.
func (lm *loggingMiddleware) EnableGroup(token, id string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("group_id", id),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Enable group failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Enable group completed successfully", args...)
	}(time.Now())

	return lm.svc.EnableGroup(token, id)
}

// DisableGroup adds logging middleware to disable group method.
func (lm *loggingMiddleware) DisableGroup(token, id string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("group_id", id),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Disable group failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Disable group completed successfully", args...)
	}(time.Now())

	return lm.svc.DisableGroup(token, id)
}

// ListUserGroupChannels adds logging middleware to list usergroup channels method.
func (lm *loggingMiddleware) ListUserGroupChannels(token, id string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("group_id", id),
			slog.Uint64("page", page),
			slog.Uint64("limit", limit),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("List usergroup channels failed to complete successfully", args...)
			return
		}
		lm.logger.Info("List usergroup channels completed successfully", args...)
	}(time.Now())

	return lm.svc.ListUserGroupChannels(token, id, page, limit)
}

// Publish adds logging middleware to publish method.
func (lm *loggingMiddleware) Publish(channelID, thingKey string, message ui.Message) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("channel_id", channelID),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Publish message failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Publish message completed successfully", args...)
	}(time.Now())

	return lm.svc.Publish(channelID, thingKey, message)
}

// ReadMessages adds logging middleware to read messages method.
func (lm *loggingMiddleware) ReadMessages(token, channelID, thingKey string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("channel_id", channelID),
			slog.Uint64("page", page),
			slog.Uint64("limit", limit),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Read messages failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Read messages completed successfully", args...)
	}(time.Now())

	return lm.svc.ReadMessages(token, channelID, thingKey, page, limit)
}

// CreateBootstrap adds logging middleware to create bootstrap method.
func (lm *loggingMiddleware) CreateBootstrap(token string, config ...sdk.BootstrapConfig) (err error) {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		if err != nil {
			lm.logger.Warn("Create bootstrap failed to complete successfully", slog.Any("error", err), duration)
			return
		}
		lm.logger.Info("Create bootstrap completed successfully", duration)
	}(time.Now())

	return lm.svc.CreateBootstrap(token, config...)
}

// ListBootstrap adds logging middleware to list bootstrap method.
func (lm *loggingMiddleware) ListBootstrap(token string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Uint64("page", page),
			slog.Uint64("limit", limit),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("List bootstraps failed to complete successfully", args...)
			return
		}
		lm.logger.Info("List bootstraps completed successfully", args...)
	}(time.Now())

	return lm.svc.ListBootstrap(token, page, limit)
}

// UpdateBootstrap adds logging middleware to update bootstrap method.
func (lm *loggingMiddleware) UpdateBootstrap(token string, config sdk.BootstrapConfig) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),

			slog.Group("config", slog.String("thing_id", config.ThingID), slog.String("name", config.Name), slog.String("content", config.Content)),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Update bootstrap failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Update bootstrap completed successfully", args...)
	}(time.Now())

	return lm.svc.UpdateBootstrap(token, config)
}

// UpdateBootstrapConnections adds logging middleware to update bootstrap connections method.
func (lm *loggingMiddleware) UpdateBootstrapConnections(token string, config sdk.BootstrapConfig) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("config", slog.String("thing_id", config.ThingID), slog.Any("channels", config.Channels)),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Update bootstrap connections failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Update bootstrap connections completed successfully", args...)
	}(time.Now())

	return lm.svc.UpdateBootstrapConnections(token, config)
}

// UpdateBootstrapCerts adds logging middleware to update bootstrap certs method.
func (lm *loggingMiddleware) UpdateBootstrapCerts(token string, config sdk.BootstrapConfig) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("config", slog.String("thing_id", config.ThingID)),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Update bootstrap certs failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Update bootstrap certs completed successfully", args...)
	}(time.Now())

	return lm.svc.UpdateBootstrapCerts(token, config)
}

// DeleteBootstrap adds logging middleware to delete bootstrap method.
func (lm *loggingMiddleware) DeleteBootstrap(token string, thingID string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("thing_id", thingID),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Delete bootstrap failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Delete bootstrap completed successfully", args...)
	}(time.Now())

	return lm.svc.DeleteBootstrap(token, thingID)
}

// UpdateBootstrapState adds logging middleware to update bootstrap state method.
func (lm *loggingMiddleware) UpdateBootstrapState(token string, config sdk.BootstrapConfig) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("thing_id", config.ThingID),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Update bootstrap state failed to complete successfully", args...)
			return
		}

		lm.logger.Info("Update bootstrap state completed successfully", args...)
	}(time.Now())

	return lm.svc.UpdateBootstrapState(token, config)
}

// ViewBootstrap adds logging middleware to view bootstrap method.
func (lm *loggingMiddleware) ViewBootstrap(token string, thingID string) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("thing_id", thingID),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("View bootstrap failed to complete successfully", args...)
			return
		}
		lm.logger.Info("View bootstrap completed successfully", args...)
	}(time.Now())

	return lm.svc.ViewBootstrap(token, thingID)
}

// GetRemoteTerminal adds logging middleware to remote terminal.
func (lm *loggingMiddleware) GetRemoteTerminal(thingID string) (res []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("thing_id", thingID),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("View remote terminal failed to complete successfully", args...)
			return
		}
		lm.logger.Info("View remote terminal completed successfully", args...)
	}(time.Now())

	return lm.svc.GetRemoteTerminal(thingID)
}

// ProcessTerminalCommand adds logging middleware to async function ProcessTerminalCommand.
func (lm *loggingMiddleware) ProcessTerminalCommand(ctx context.Context, thingID, token, command string, res chan string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("thing_id", thingID),
			slog.String("command", command),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Process terminal command failed to complete successfully", args...)
		}
		lm.logger.Info("Process terminal command completed successfully", args...)
	}(time.Now())

	return lm.svc.ProcessTerminalCommand(ctx, thingID, token, command, res)
}

// GetEntities adds logging middleware to get entities method.
func (lm *loggingMiddleware) GetEntities(token, entityType, entityName, domainID, permission string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("entity", slog.String("type", entityType), slog.String("name", entityName)),
			slog.String("domain_id", domainID),
			slog.String("permission", permission),
			slog.Uint64("page", page),
			slog.Uint64("limit", limit),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Get entities failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Get entities completed successfully", args...)
	}(time.Now())

	return lm.svc.GetEntities(token, entityType, entityName, domainID, permission, page, limit)
}

// ErrorPage adds logging middleware to error page method.
func (lm *loggingMiddleware) ErrorPage(errMsg string) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("error", errMsg),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Error page failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Error page completed successfully", args...)
	}(time.Now())

	return lm.svc.ErrorPage(errMsg)
}

// DomainLogin adds logging middleware to domain login method.
func (lm *loggingMiddleware) DomainLogin(login sdk.Login, refreshToken string) (token sdk.Token, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("domain_id", login.DomainID),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Domain login failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Domain login completed successfully", args...)
	}(time.Now())

	return lm.svc.DomainLogin(login, refreshToken)
}

// ListDomains adds logging middleware to list domains method.
func (lm *loggingMiddleware) ListDomains(token, status string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("status", status),
			slog.Uint64("page", page),
			slog.Uint64("limit", limit),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("List domains failed to complete successfully", args...)
		}
		lm.logger.Info("List domains completed successfully", args...)
	}(time.Now())

	return lm.svc.ListDomains(token, status, page, limit)
}

// CreateDomain adds logging middleware to create domain method.
func (lm *loggingMiddleware) CreateDomain(token string, domain sdk.Domain) (err error) {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		if err != nil {
			lm.logger.Warn("Create domain failed to complete successfully", slog.Any("error", err), duration)
		}
		lm.logger.Info("Create domain completed successfully", duration)
	}(time.Now())

	return lm.svc.CreateDomain(token, domain)
}

// UpdateDomain adds logging middleware to update domain method.
func (lm *loggingMiddleware) UpdateDomain(token string, domain sdk.Domain) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Group("domain", slog.String("id", domain.ID), slog.String("name", domain.Name), slog.Any("tags", domain.Tags), slog.Any("metadata", domain.Metadata)),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Update domain failed to complete successfully", args...)
		}
		lm.logger.Info("Update domain completed successfully", args...)
	}(time.Now())

	return lm.svc.UpdateDomain(token, domain)
}

// Domain adds logging middleware to domain method.
func (lm *loggingMiddleware) Domain(token, id string) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("domain_id", id),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("View domain failed to complete successfully", args...)
		}
		lm.logger.Info("View domain completed successfully", args...)
	}(time.Now())

	return lm.svc.Domain(token, id)
}

// EnableDomain adds logging middleware to enable domain method.
func (lm *loggingMiddleware) EnableDomain(token, id string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("domain_id", id),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Enable domain failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Enable domain completed successfully", args...)
	}(time.Now())

	return lm.svc.EnableDomain(token, id)
}

// DisableDomain adds logging middleware to disable domain method.
func (lm *loggingMiddleware) DisableDomain(token, id string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("domain_id", id),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Disable domain failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Disable domain completed successfully", args...)
	}(time.Now())

	return lm.svc.DisableDomain(token, id)
}

// AssignMember adds logging middleware to assign member method.
func (lm *loggingMiddleware) AssignMember(token, domainID string, req sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("domain_id", domainID),
			slog.Any("user_ids", req.UserIDs),
			slog.String("relation", req.Relation),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Assign member failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Assign member completed successfully", args...)
	}(time.Now())

	return lm.svc.AssignMember(token, domainID, req)
}

// UnassignMember adds logging middleware to unassign member method.
func (lm *loggingMiddleware) UnassignMember(token, domainID string, req sdk.UsersRelationRequest) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("domain_id", domainID),
			slog.Any("user_ids", req.UserIDs),
			slog.String("relation", req.Relation),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Unassign member failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Unassign member completed successfully", args...)
	}(time.Now())

	return lm.svc.UnassignMember(token, domainID, req)
}

// ViewMember adds logging middleware to view member method.
func (lm *loggingMiddleware) ViewMember(token, identity string) (b []byte, err error) {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		if err != nil {
			lm.logger.Warn("View member failed to complete successfully", slog.Any("error", err), duration)
			return
		}
		lm.logger.Info("View member completed successfully", duration)
	}(time.Now())

	return lm.svc.ViewMember(token, identity)
}

// Members adds logging middleware to members method.
func (lm *loggingMiddleware) Members(token, domainID string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("domain_id", domainID),
			slog.Uint64("page", page),
			slog.Uint64("limit", limit),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Members failed to complete successfully", args...)
		}
		lm.logger.Info("Members completed successfully", args...)
	}(time.Now())

	return lm.svc.Members(token, domainID, page, limit)
}

// SendInvitation adds logging middleware to send invitation method.
func (lm *loggingMiddleware) SendInvitation(token string, invitation sdk.Invitation) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("invited", invitation.UserID),
			slog.String("inviter", invitation.InvitedBy),
			slog.String("domain", invitation.DomainID),
			slog.String("relation", invitation.Relation),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Send invitation failed to complete successfully", args...)
		}
		lm.logger.Info("Send invitation completed successfully", args...)
	}(time.Now())

	return lm.svc.SendInvitation(token, invitation)
}

// Invitations adds logging middleware to invitations method.
func (lm *loggingMiddleware) Invitations(token, domainID string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("domain_id", domainID),
			slog.Uint64("page", page),
			slog.Uint64("limit", limit),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Invitations failed to complete successfully", args...)
		}
		lm.logger.Info("Invitations completed successfully", args...)
	}(time.Now())

	return lm.svc.Invitations(token, domainID, page, limit)
}

// AcceptInvitation adds logging middleware to accept invitation method.
func (lm *loggingMiddleware) AcceptInvitation(token, domainID string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("domain_id", domainID),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Accept invitation failed to complete successfully", args...)
		}
		lm.logger.Info("Accept invitation completed successfully", args...)
	}(time.Now())

	return lm.svc.AcceptInvitation(token, domainID)
}

// DeleteInvitation adds logging middleware to delete invitation method.
func (lm *loggingMiddleware) DeleteInvitation(token, userID, domainID string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("domain_id", domainID),
			slog.String("user_id", userID),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Delete invitation failed to complete successfully", args...)
		}
		lm.logger.Info("Delete invitation completed successfully", args...)
	}(time.Now())

	return lm.svc.DeleteInvitation(token, userID, domainID)
}

// ViewDashboard adds logging middleware to view dashboard method.
func (lm *loggingMiddleware) ViewDashboard(token, dashboardID string) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("dashboard_id", dashboardID),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("View dashboard failed to complete successfully", args...)
			return
		}
		lm.logger.Info("View dashboard completed successfully", args...)
	}(time.Now())

	return lm.svc.ViewDashboard(token, dashboardID)
}

// CreateDashboard adds logging middleware to create dashboard method.
func (lm *loggingMiddleware) CreateDashboard(token string, dashboardReq ui.DashboardReq) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("dashboard_name", dashboardReq.Name),
			slog.String("description", dashboardReq.Description),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Create dashboard failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Create dashboard completed successfully", args...)
	}(time.Now())

	return lm.svc.CreateDashboard(token, dashboardReq)
}

// ListDashboards adds logging middleware to list dashboards method.
func (lm *loggingMiddleware) ListDashboards(token string, page, limit uint64) (b []byte, err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.Uint64("page", page),
			slog.Uint64("limit", limit),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("List dashboards failed to complete successfully", args...)
			return
		}
		lm.logger.Info("List dashboards completed successfully", args...)
	}(time.Now())

	return lm.svc.ListDashboards(token, page, limit)
}

// Dashboards adds logging middleware to dashboards method.
func (lm *loggingMiddleware) Dashboards() (b []byte, err error) {
	defer func(begin time.Time) {
		duration := slog.String("duration", time.Since(begin).String())
		if err != nil {
			lm.logger.Warn("Dashboards failed to complete successfully", slog.Any("error", err), duration)
			return
		}
		lm.logger.Info("Dashboards completed successfully", duration)
	}(time.Now())

	return lm.svc.Dashboards()
}

// UpdateDashboard adds logging middleware to update dashboard method.
func (lm *loggingMiddleware) UpdateDashboard(token, dashboardID string, dashboardReq ui.DashboardReq) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("dashboard_id", dashboardID),
			slog.String("dashboard_name", dashboardReq.Name),
			slog.String("description", dashboardReq.Description),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Update dashboard failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Update dashboard completed successfully", args...)
	}(time.Now())

	return lm.svc.UpdateDashboard(token, dashboardID, dashboardReq)
}

// DeleteDashboard adds logging middleware to delete dashboard method.
func (lm *loggingMiddleware) DeleteDashboard(token, dashboardID string) (err error) {
	defer func(begin time.Time) {
		args := []any{
			slog.String("duration", time.Since(begin).String()),
			slog.String("dashboard_id", dashboardID),
		}
		if err != nil {
			args = append(args, slog.Any("error", err))
			lm.logger.Warn("Delete dashboards failed to complete successfully", args...)
			return
		}
		lm.logger.Info("Delete dashboards completed successfully", args...)
	}(time.Now())

	return lm.svc.DeleteDashboard(token, dashboardID)
}
