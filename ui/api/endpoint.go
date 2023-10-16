// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"

	"golang.org/x/sync/errgroup"

	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/ultravioletrs/mainflux-ui/ui"

	"github.com/go-kit/kit/endpoint"
	sdk "github.com/mainflux/mainflux/pkg/sdk/go"
)

func indexEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(indexReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.Index(req.token)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func loginEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, _ interface{}) (interface{}, error) {
		res, err := svc.Login()
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func showUpdatePasswordEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(showUpdatePasswordReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.PasswordUpdate(req.token)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func updatePasswordEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserPasswordReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.UpdatePassword(req.token, req.OldPass, req.NewPass); err != nil {
			return nil, err
		}

		cookies := []*http.Cookie{
			{
				Name:     "token",
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
			},
			{
				Name:     "refresh_token",
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
			},
		}

		return uiRes{
			code:    http.StatusFound,
			cookies: cookies,
			headers: map[string]string{"Location": "/login"},
		}, nil
	}
}

func tokenEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(tokenReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		credentials := sdk.Credentials{
			Identity: req.Identity,
			Secret:   req.Secret,
		}
		user := sdk.User{
			Credentials: credentials,
		}

		token, err := svc.Token(user)
		if err != nil {
			return nil, errors.Wrap(errUnauthorized, err)
		}

		cookies := []*http.Cookie{
			{
				Name:     "token",
				Value:    token.AccessToken,
				Path:     "/",
				HttpOnly: true,
			},
			{
				Name:     "refresh_token",
				Value:    token.RefreshToken,
				Path:     "/",
				HttpOnly: true,
			},
		}

		tkr := uiRes{
			code:    http.StatusFound,
			cookies: cookies,
			headers: map[string]string{"Location": "/"},
		}

		return tkr, nil
	}
}

func refreshTokenEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(refreshTokenReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		token, err := svc.RefreshToken(req.refreshToken)
		if err != nil {
			return nil, errors.Wrap(errUnauthorized, err)
		}

		cookies := []*http.Cookie{
			{
				Name:     "token",
				Value:    token.AccessToken,
				Path:     "/",
				HttpOnly: true,
			},
			{
				Name:     "refresh_token",
				Value:    token.RefreshToken,
				Path:     "/",
				HttpOnly: true,
			},
		}

		tkr := uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": req.ref},
			cookies: cookies,
		}

		return tkr, nil
	}
}

func logoutEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, _ interface{}) (interface{}, error) {
		if err := svc.Logout(); err != nil {
			return nil, err
		}

		cookies := []*http.Cookie{
			{
				Name:     "token",
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
			},
			{
				Name:     "refresh_token",
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
			},
		}
		return uiRes{
			code:    http.StatusFound,
			cookies: cookies,
			headers: map[string]string{"Location": "/login"},
		}, nil
	}
}

func passwordResetRequestEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(passwordResetRequestReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.PasswordResetRequest(req.Email); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/login"},
		}, nil
	}
}

func passwordResetEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(passwordResetReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.PasswordReset(req.token, req.Password, req.ConfirmPassword); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/login"},
		}, nil
	}
}

func showPasswordResetEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, _ interface{}) (interface{}, error) {
		res, err := svc.ShowPasswordReset()
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func createUserEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(createUserReq)

		if err := req.validate(); err != nil {
			return nil, err
		}
		if err := svc.CreateUsers(req.token, req.User); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusOK,
			headers: map[string]string{"Location": "/users"},
		}, nil
	}
}

func createUsersEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(createUsersReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		users := []sdk.User{}
		for i := range req.Emails {
			credential := sdk.Credentials{
				Identity: req.Emails[i],
				Secret:   req.Passwords[i],
			}
			user := sdk.User{
				Name:        req.Names[i],
				Credentials: credential,
			}
			users = append(users, user)
		}
		if err := svc.CreateUsers(req.token, users...); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusOK,
			headers: map[string]string{"Location": "/users"},
		}, nil
	}
}

func listUsersEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(listEntityReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListUsers(req.token, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func viewUserEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(viewResourceReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ViewUser(req.token, req.id)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func updateUserEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		user := sdk.User{
			ID:       req.id,
			Name:     req.Name,
			Metadata: req.Metadata,
		}

		if err := svc.UpdateUser(req.token, req.id, user); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/users/" + req.id},
		}, nil
	}
}

func updateUserTagsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserTagsReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		user := sdk.User{
			ID:   req.id,
			Tags: req.Tags,
		}
		if err := svc.UpdateUserTags(req.token, req.id, user); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/users/" + req.id},
		}, nil
	}
}

func updateUserIdentityEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserIdentityReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		credential := sdk.Credentials{
			Identity: req.Identity,
		}
		user := sdk.User{
			ID:          req.id,
			Credentials: credential,
		}
		if err := svc.UpdateUserIdentity(req.token, req.id, user); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/users/" + req.id},
		}, nil
	}
}

func enableUserEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.EnableUser(req.token, req.UserID); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/users"},
		}, nil
	}
}

func disableUserEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.DisableUser(req.token, req.UserID); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/users"},
		}, nil
	}
}

func createThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(createThingReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.CreateThings(req.token, req.Thing); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/things"},
		}, nil
	}
}

func createThingsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(createThingsReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		things := []sdk.Thing{}
		for i := range req.Names {
			th := sdk.Thing{
				Name: req.Names[i],
			}
			things = append(things, th)
		}
		if err := svc.CreateThings(req.token, things...); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/things"},
		}, nil
	}
}

func listThingsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(listEntityReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListThings(req.token, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func viewThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(viewResourceReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ViewThing(req.token, req.id)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func updateThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateThingReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		uth := sdk.Thing{
			ID:       req.id,
			Name:     req.Name,
			Metadata: req.Metadata,
		}

		if err := svc.UpdateThing(req.token, req.id, uth); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/things/" + req.id},
		}, nil
	}
}

func updateThingTagsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateThingTagsReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		thing := sdk.Thing{
			ID:   req.id,
			Tags: req.Tags,
		}
		if err := svc.UpdateThingTags(req.token, req.id, thing); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/things/" + req.id},
		}, nil
	}
}

func updateThingSecretEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateThingSecretReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.UpdateThingSecret(req.token, req.id, req.Secret); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/things/" + req.id},
		}, nil
	}
}

func enableThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateThingStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.EnableThing(req.token, req.ThingID); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/things"},
		}, nil
	}
}

func disableThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateThingStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.DisableThing(req.token, req.ThingID); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/things"},
		}, nil
	}
}

func updateThingOwnerEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateThingOwnerReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		thing := sdk.Thing{
			ID:    req.id,
			Owner: req.Owner,
		}
		if err := svc.UpdateThingOwner(req.token, thing); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/things/" + req.id},
		}, nil
	}
}

func createChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(createChannelReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.CreateChannels(req.token, req.Channel); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/channels"},
		}, nil
	}
}

func createChannelsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(createChannelsReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		channels := []sdk.Channel{}
		for i := range req.Names {
			ch := sdk.Channel{
				Name: req.Names[i],
			}
			channels = append(channels, ch)
		}
		if err := svc.CreateChannels(req.token, channels...); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/channels"},
		}, nil
	}
}

func viewChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(viewResourceReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ViewChannel(req.token, req.id)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func updateChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateChannelReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		uch := sdk.Channel{
			ID:          req.id,
			Name:        req.Name,
			Metadata:    req.Metadata,
			Description: req.Description,
		}

		if err := svc.UpdateChannel(req.token, req.id, uch); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/channels/" + req.id},
		}, nil
	}
}

func listChannelsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(listEntityReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListChannels(req.token, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func connectEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		cr := request.(connectReq)
		if err := cr.validate(); err != nil {
			return nil, err
		}

		if err := svc.Connect(cr.token, cr.ConnIDs); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/channels/" + cr.ConnIDs.ChannelIDs[0] + "/things"},
		}, nil
	}
}

func disconnectEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		dcr := request.(disconnectReq)
		if err := dcr.validate(); err != nil {
			return nil, err
		}

		if err := svc.Disconnect(dcr.token, dcr.ConnIDs); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/channels/" + dcr.ConnIDs.ChannelIDs[0] + "/things"},
		}, nil
	}
}

func connectThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		cr := request.(connectThingReq)
		if err := cr.validate(); err != nil {
			return nil, err
		}

		if err := svc.ConnectThing(cr.token, cr.ConnIDs); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/channels/" + cr.ConnIDs.ChannelIDs[0] + "/things"},
		}, nil
	}
}

func shareThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		sr := request.(shareThingReq)
		if err := sr.validate(); err != nil {
			return nil, err
		}

		if err := svc.ShareThing(sr.token, sr.ChanID, sr.UserID, sr.Actions); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/channels/" + sr.ChanID + "/things"},
		}, nil
	}
}

func connectChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		cr := request.(connectChannelReq)
		if err := cr.validate(); err != nil {
			return nil, err
		}

		if err := svc.ConnectChannel(cr.token, cr.ConnIDs); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/things/" + cr.ConnIDs.ThingIDs[0] + "/channels"},
		}, nil
	}
}

func disconnectThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		dcr := request.(disconnectThingReq)
		if err := dcr.validate(); err != nil {
			return nil, err
		}

		if err := svc.DisconnectThing(dcr.ThingID, dcr.ChanID, dcr.token); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/channels/" + dcr.ChanID + "/things"},
		}, nil
	}
}

func disconnectChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		dcr := request.(disconnectChannelReq)
		if err := dcr.validate(); err != nil {
			return nil, err
		}

		if err := svc.DisconnectChannel(dcr.ThingID, dcr.ChanID, dcr.token); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/things/" + dcr.ThingID + "/channels"},
		}, nil
	}
}

func listThingsByChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(listEntityByIDReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListThingsByChannel(req.token, req.id, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func listChannelsByThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(listEntityByIDReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListChannelsByThing(req.token, req.id, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func enableChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateChannelStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.EnableChannel(req.token, req.ChannelID); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/channels"},
		}, nil
	}
}

func disableChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateChannelStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.DisableChannel(req.token, req.ChannelID); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/channels"},
		}, nil
	}
}

func listThingsPoliciesEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(listEntityReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.ListThingsPolicies(req.token, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func addThingsPolicyEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(addThingsPolicyReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.AddThingsPolicy(req.token, req.Policy); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/things/policies"},
		}, nil
	}
}

func updateThingsPolicyEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updatePolicyReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.UpdateThingsPolicy(req.token, req.Policy); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/things/policies"},
		}, nil
	}
}

func deleteThingsPolicyEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(deleteThingsPolicyReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.DeleteThingsPolicy(req.token, req.Policy); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/things/policies"},
		}, nil
	}
}

func createGroupEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		cgr := request.(createGroupReq)
		if err := cgr.validate(); err != nil {
			return nil, err
		}

		if err := svc.CreateGroups(cgr.token, cgr.Group); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/groups"},
		}, nil
	}
}

func createGroupsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(createGroupsReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		groups := []sdk.Group{}
		for i := range req.Names {
			gr := sdk.Group{
				Name: req.Names[i],
			}
			groups = append(groups, gr)
		}
		if err := svc.CreateGroups(req.token, groups...); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/groups"},
		}, nil
	}
}

func listGroupsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(listEntityReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListGroups(req.token, req.page, req.limit)
		if err != nil {
			return nil, err
		}
		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func listGroupMembersEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(listEntityByIDReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListGroupMembers(req.token, req.id, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func viewGroupEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(viewResourceReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ViewGroup(req.token, req.id)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func updateGroupEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateGroupReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		ugr := sdk.Group{
			ID:          req.id,
			Name:        req.Name,
			Metadata:    req.Metadata,
			Description: req.Description,
		}

		if err := svc.UpdateGroup(req.token, req.id, ugr); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/groups/" + req.id},
		}, nil
	}
}

func assignEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(assignReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.Assign(req.token, req.groupID, req.MemberID, req.Type); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/groups/" + req.groupID + "/members"},
		}, nil
	}
}

func unassignEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(unassignReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.Unassign(req.token, req.groupID, req.MemberID); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/groups/" + req.groupID + "/members"},
		}, nil
	}
}

func enableGroupEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateGroupStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.EnableGroup(req.token, req.GroupID); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/groups"},
		}, nil
	}
}

func disableGroupEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateGroupStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.DisableGroup(req.token, req.GroupID); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/groups"},
		}, nil
	}
}

func listPoliciesEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(listEntityReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListPolicies(req.token, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func addPolicyEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(addPolicyReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.AddPolicy(req.token, req.Policy); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/users/policies"},
		}, nil
	}
}

func updatePolicyEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updatePolicyReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.UpdatePolicy(req.token, req.Policy); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/users/policies"},
		}, nil
	}
}

func deletePolicyEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(deletePolicyReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.DeletePolicy(req.token, req.Policy); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/users/policies"},
		}, nil
	}
}

func publishMessageEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(publishReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.Publish(req.token, req.thingKey, req.Msg); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/channels/" + req.Msg.Channel + "/things"},
		}, nil
	}
}

func readMessageEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(readMessageReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ReadMessage(req.token)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func wsConnectionEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(wsConnectionReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.WsConnection(req.token, req.ChanID, req.ThingKey)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, nil
	}
}

func getTerminalEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(viewResourceReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.GetRemoteTerminal(req.id, req.token)
		if err != nil {
			return nil, err
		}
		return uiRes{
			html: res,
		}, nil
	}
}

func handleTerminalInputEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(bootstrapCommandReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		// Create a channel to receive the command result
		ch := make(chan string)

		g, ctx := errgroup.WithContext(ctx)

		// Start a goroutine to process the command asynchronously
		g.Go(func() error {
			return svc.ProcessTerminalCommand(ctx, req.id, req.token, req.command, ch)
		})

		if err := g.Wait(); err != nil {
			return nil, err
		}

		// Receive the command result from the channel
		result := <-ch

		return terminalResponse{
			Command: req.command,
			Result:  result,
		}, nil
	}
}

func viewBootstrap(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(viewResourceReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ViewBootstrap(req.token, req.id)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func listBootstrap(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(listEntityReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListBootstrap(req.token, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func updateBootstrap(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(updateBootstrapReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		cfg := sdk.BootstrapConfig{
			ThingID: req.id,
			Name:    req.Name,
			Content: req.Content,
		}
		if err := svc.UpdateBootstrap(req.token, cfg); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/bootstrap/" + req.id},
		}, nil
	}
}

func updateBootstrapCerts(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(updateBootstrapCertReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		cfg := sdk.BootstrapConfig{
			ThingID:    req.thingID,
			ClientCert: req.ClientCert,
			ClientKey:  req.ClientKey,
			CACert:     req.CACert,
		}
		if err := svc.UpdateBootstrapCerts(req.token, cfg); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/bootstrap/" + req.thingID},
		}, nil
	}
}

func updateBootstrapConnections(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(updateBootstrapConnReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		cfg := sdk.BootstrapConfig{
			ThingID:  req.id,
			Channels: req.Channels,
		}
		if err := svc.UpdateBootstrapConnections(req.token, cfg); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/bootstrap/" + req.id},
		}, nil
	}
}

func createBootstrap(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(createBootstrapReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		cfg := sdk.BootstrapConfig{
			ThingID:     req.ThingID,
			Channels:    req.Channels,
			ExternalID:  req.ExternalID,
			ExternalKey: req.ExternalKey,
			Name:        req.Name,
			ClientCert:  req.ClientCert,
			ClientKey:   req.ClientKey,
			CACert:      req.CACert,
			Content:     req.Content,
		}
		if err := svc.CreateBootstrap(req.token, cfg); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Location": "/bootstraps"},
		}, nil
	}
}

func getEntitiesEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(getEntitiesReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.GetEntities(req.token, req.Item, req.Name, req.Page, req.Limit)
		if err != nil {
			return nil, err
		}
		return uiRes{
			html:    res,
			code:    http.StatusOK,
			headers: map[string]string{"Content-Type": "application/json"},
		}, nil
	}
}
