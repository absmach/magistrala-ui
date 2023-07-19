// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"

	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/ultravioletrs/mainflux-ui/ui"

	"github.com/go-kit/kit/endpoint"
	sdk "github.com/mainflux/mainflux/pkg/sdk/go"
)

func indexEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(indexReq)
		res, err := svc.Index(ctx, req.token)

		return uiRes{
			html: res,
		}, err
	}
}

func loginEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		res, err := svc.Login(ctx)

		return uiRes{
			code: 0,
			html: res,
		}, err
	}
}

func showUpdatePasswordEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		res, err := svc.PasswordReset(ctx)

		return uiRes{
			code: 0,
			html: res,
		}, err
	}
}

func tokenEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(tokenReq)
		credentials := sdk.Credentials{
			Identity: req.Identity,
			Secret:   req.Secret,
		}
		user := sdk.User{
			Credentials: credentials,
		}

		token, err := svc.Token(ctx, user)
		if err != nil {
			return nil, errors.Wrap(errUnauthorized, err)
		}

		accessToken := token.AccessToken
		refreshToken := token.RefreshToken

		cookies := []*http.Cookie{
			{
				Name:     "token",
				Value:    accessToken,
				Path:     "/",
				HttpOnly: true,
			},
			{
				Name:     "refresh_token",
				Value:    refreshToken,
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
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(refreshTokenReq)

		token, err := svc.RefreshToken(ctx, req.RefreshToken)
		if err != nil {
			return nil, errors.Wrap(errUnauthorized, err)
		}

		newAccessToken := token.AccessToken
		newRefreshToken := token.RefreshToken

		cookies := []*http.Cookie{
			{
				Name:     "token",
				Value:    newAccessToken,
				Path:     "/",
				HttpOnly: true,
			},
			{
				Name:     "refresh_token",
				Value:    newRefreshToken,
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
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		res, err := svc.Logout(ctx)

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
			html:    res,
			cookies: cookies,
			headers: map[string]string{"Location": "/login"},
		}, err
	}
}

func createUserEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createUserReq)

		if err := req.validate(); err != nil {
			return nil, err
		}
		user := req.user
		res, err := svc.CreateUsers(ctx, req.token, user)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func createUsersEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
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
		res, err := svc.CreateUsers(ctx, req.token, users...)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			html:    res,
			headers: map[string]string{"Location": "/users"},
		}, err
	}
}

func listUsersEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listUsersReq)

		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.ListUsers(ctx, req.token)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func viewUserEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewResourceReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ViewUser(ctx, req.token, req.id)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func updateUserEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		user := sdk.User{
			ID:       req.id,
			Name:     req.Name,
			Metadata: req.Metadata,
		}

		res, err := svc.UpdateUser(ctx, req.token, req.id, user)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func updateUserTagsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserTagsReq)

		if err := req.validate(); err != nil {
			return nil, err
		}
		user := sdk.User{
			ID:   req.id,
			Tags: req.Tags,
		}
		res, err := svc.UpdateUserTags(ctx, req.token, req.id, user)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func updateUserIdentityEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
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
		res, err := svc.UpdateUserIdentity(ctx, req.token, req.id, user)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func enableUserEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.EnableUser(ctx, req.token, req.UserID)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			html:    res,
			headers: map[string]string{"Location": "/users"},
		}, err
	}
}

func disableUserEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.DisableUser(ctx, req.token, req.UserID)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			html:    res,
			headers: map[string]string{"Location": "/users"},
		}, err
	}
}

func updatePasswordEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserPasswordReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.UpdatePassword(ctx, req.token, req.OldPass, req.NewPass)
		if err != nil {
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
			html:    res,
			cookies: cookies,
			headers: map[string]string{"Location": "/login"},
		}, err
	}
}

func createThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createThingReq)

		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.CreateThing(ctx, req.token, req.thing)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func createThingsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
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
		res, err := svc.CreateThings(ctx, req.token, things...)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			html:    res,
			headers: map[string]string{"Location": "/things"},
		}, err
	}
}

func listThingsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listThingsReq)

		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.ListThings(ctx, req.token)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func viewThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewResourceReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ViewThing(ctx, req.token, req.id)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func updateThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateThingReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		uth := sdk.Thing{
			ID:       req.id,
			Name:     req.Name,
			Metadata: req.Metadata,
		}

		res, err := svc.UpdateThing(ctx, req.token, req.id, uth)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func updateThingTagsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateThingTagsReq)

		if err := req.validate(); err != nil {
			return nil, err
		}
		thing := sdk.Thing{
			ID:   req.id,
			Tags: req.Tags,
		}
		res, err := svc.UpdateThingTags(ctx, req.token, req.id, thing)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func updateThingSecretEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateThingSecretReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.UpdateThingSecret(ctx, req.token, req.id, req.Secret)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func enableThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateThingStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.EnableThing(ctx, req.token, req.ThingID)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			html:    res,
			headers: map[string]string{"Location": "/things"},
		}, err
	}
}

func disableThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateThingStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.DisableThing(ctx, req.token, req.ThingID)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			html:    res,
			headers: map[string]string{"Location": "/things"},
		}, err
	}
}

func updateThingOwnerEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateThingOwnerReq)

		if err := req.validate(); err != nil {
			return nil, err
		}
		thing := sdk.Thing{
			ID:    req.id,
			Owner: req.Owner,
		}
		res, err := svc.UpdateThingOwner(ctx, req.token, req.id, thing)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func createChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createChannelReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.CreateChannel(ctx, req.token, req.Channel)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func createChannelsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
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
		res, err := svc.CreateChannels(ctx, req.token, channels...)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			html:    res,
			headers: map[string]string{"Location": "/channels"},
		}, err
	}
}

func viewChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewResourceReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ViewChannel(ctx, req.token, req.id)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func updateChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
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

		res, err := svc.UpdateChannel(ctx, req.token, req.id, uch)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func listChannelsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listChannelsReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListChannels(ctx, req.token)

		return uiRes{
			html: res,
		}, err
	}
}

func connectEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		cr := request.(connectReq)

		if err := cr.validate(); err != nil {
			return nil, err
		}

		res, err := svc.Connect(ctx, cr.token, cr.ConnIDs)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func disconnectEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		dcr := request.(disconnectReq)

		if err := dcr.validate(); err != nil {
			return nil, err
		}

		res, err := svc.Disconnect(ctx, dcr.token, dcr.ConnIDs)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func connectThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		cr := request.(connectThingReq)

		if err := cr.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ConnectThing(ctx, cr.token, cr.ConnIDs)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func shareThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		sr := request.(shareThingReq)

		if err := sr.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ShareThing(ctx, sr.token, sr.ChanID, sr.UserID, sr.Actions)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func connectChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		cr := request.(connectChannelReq)

		if err := cr.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ConnectChannel(ctx, cr.token, cr.ConnIDs)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func disconnectThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		dcr := request.(disconnectThingReq)

		if err := dcr.validate(); err != nil {
			return nil, err
		}

		res, err := svc.DisconnectThing(ctx, dcr.ThingID, dcr.ChanID, dcr.token)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func disconnectChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		dcr := request.(disconnectChannelReq)

		if err := dcr.validate(); err != nil {
			return nil, err
		}

		res, err := svc.DisconnectChannel(ctx, dcr.ThingID, dcr.ChanID, dcr.token)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func listThingsByChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewResourceReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListThingsByChannel(ctx, req.token, req.id)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func listChannelsByThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewResourceReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListChannelsByThing(ctx, req.token, req.id)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func enableChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateChannelStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.EnableChannel(ctx, req.token, req.ChannelID)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			html:    res,
			headers: map[string]string{"Location": "/channels"},
		}, err
	}
}

func disableChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateChannelStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.DisableChannel(ctx, req.token, req.ChannelID)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			html:    res,
			headers: map[string]string{"Location": "/channels"},
		}, err
	}
}

func listThingsPoliciesEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listPoliciesReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.ListThingsPolicies(ctx, req.token)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func addThingsPolicyEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(addThingsPolicyReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.AddThingsPolicy(ctx, req.token, req.ConnIDs)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func updateThingsPolicyEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updatePolicyReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.UpdateThingsPolicy(ctx, req.token, req.Policy)
		if err != nil {
			return nil, err
		}
		return uiRes{
			html: res,
		}, err
	}
}

func deleteThingsPolicyEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(deleteThingsPolicyReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.DeleteThingsPolicy(ctx, req.token, req.ConnIDs)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func createGroupEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		cgr := request.(createGroupReq)

		if err := cgr.validate(); err != nil {
			return nil, err
		}

		res, err := svc.CreateGroups(ctx, cgr.token, cgr.Group)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func createGroupsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
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
		res, err := svc.CreateGroups(ctx, req.token, groups...)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			html:    res,
			headers: map[string]string{"Location": "/groups"},
		}, err
	}
}

func listGroupsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listGroupsReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListGroups(ctx, req.token)
		return uiRes{
			html: res,
		}, err
	}
}

func listGroupMembersEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewResourceReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListGroupMembers(ctx, req.token, req.id)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func viewGroupEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewResourceReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ViewGroup(ctx, req.token, req.id)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func updateGroupEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
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

		res, err := svc.UpdateGroup(ctx, req.token, req.id, ugr)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func assignEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(assignReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.Assign(ctx, req.token, req.groupID, req.MemberID, req.Type)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func unassignEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(unassignReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.Unassign(ctx, req.token, req.groupID, req.MemberID)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func enableGroupEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateGroupStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.EnableGroup(ctx, req.token, req.GroupID)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			html:    res,
			headers: map[string]string{"Location": "/groups"},
		}, err
	}
}

func disableGroupEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateGroupStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.DisableGroup(ctx, req.token, req.GroupID)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusFound,
			html:    res,
			headers: map[string]string{"Location": "/groups"},
		}, err
	}
}

func listPoliciesEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listPoliciesReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.ListPolicies(ctx, req.token)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func addPolicyEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(addPolicyReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.AddPolicy(ctx, req.token, req.Policy)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func updatePolicyEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updatePolicyReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.UpdatePolicy(ctx, req.token, req.Policy)
		if err != nil {
			return nil, err
		}
		return uiRes{
			html: res,
		}, err
	}
}

func deletePolicyEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(deletePolicyReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.DeletePolicy(ctx, req.token, req.Policy)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func publishMessageEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(publishReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.Publish(ctx, req.token, req.thingKey, req.Msg)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func readMessageEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(readMessageReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.ReadMessage(ctx, req.token)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func wsConnectionEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(wsConnectionReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.WsConnection(ctx, req.token, req.ChanID, req.ThingKey)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}

func listDeletedClientsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listDeletedClientsReq)

		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.ListDeletedClients(ctx, req.token)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
		}, err
	}
}
