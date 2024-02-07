// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"time"

	"github.com/absmach/magistrala-ui/ui"
	sdk "github.com/absmach/magistrala/pkg/sdk/go"
	"github.com/go-kit/kit/endpoint"
	"github.com/golang-jwt/jwt"
	"golang.org/x/sync/errgroup"
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

func viewRegistrationEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, _ interface{}) (interface{}, error) {
		res, err := svc.ViewRegistration()
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func registerUserEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(registerUserReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		token, err := svc.RegisterUser(req.User)
		if err != nil {
			return nil, err
		}

		userPage, err := svc.UserProfile(token.AccessToken)
		if err != nil {
			return nil, err
		}

		accessExp, err := extractTokenExpiry(token.AccessToken)
		if err != nil {
			return nil, err
		}
		refreshExp, err := extractTokenExpiry(token.RefreshToken)
		if err != nil {
			return nil, err
		}

		tkr := uiRes{
			code: http.StatusCreated,
			html: userPage,
			cookies: []*http.Cookie{
				{
					Name:     accessTokenKey,
					Value:    token.AccessToken,
					Path:     "/",
					HttpOnly: true,
					Expires:  accessExp,
				},
				{
					Name:     refreshTokenKey,
					Value:    token.RefreshToken,
					Path:     domainsAPIEndpoint,
					HttpOnly: true,
					Expires:  refreshExp,
				},
			},
		}

		return tkr, nil
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

func logoutEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, _ interface{}) (interface{}, error) {
		if err := svc.Logout(); err != nil {
			return nil, err
		}

		cookies := []*http.Cookie{
			{
				Name:     accessTokenKey,
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
			},
			{
				Name:     refreshTokenKey,
				Value:    "",
				Path:     tokenRefreshAPIEndpoint,
				MaxAge:   -1,
				HttpOnly: true,
			},
			{
				Name:     refreshTokenKey,
				Value:    "",
				Path:     domainsAPIEndpoint,
				MaxAge:   -1,
				HttpOnly: true,
			},
		}
		return uiRes{
			code:    http.StatusSeeOther,
			cookies: cookies,
			headers: map[string]string{"Location": loginAPIEndpoint},
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
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": loginAPIEndpoint},
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
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": loginAPIEndpoint},
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
				Name:     accessTokenKey,
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
			},
			{
				Name:     refreshTokenKey,
				Value:    "",
				Path:     tokenRefreshAPIEndpoint,
				MaxAge:   -1,
				HttpOnly: true,
			},
			{
				Name:     refreshTokenKey,
				Value:    "",
				Path:     domainsAPIEndpoint,
				MaxAge:   -1,
				HttpOnly: true,
			},
		}

		return uiRes{
			code:    http.StatusSeeOther,
			cookies: cookies,
			headers: map[string]string{"Location": loginAPIEndpoint},
		}, nil
	}
}

func tokenEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(tokenReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		token, err := svc.Token(
			sdk.Login{
				Identity: req.Identity,
				Secret:   req.Secret,
			})
		if err != nil {
			return nil, err
		}

		user, err := svc.UserProfile(token.AccessToken)
		if err != nil {
			return nil, err
		}

		accessExp, err := extractTokenExpiry(token.AccessToken)
		if err != nil {
			return nil, err
		}
		refreshExp, err := extractTokenExpiry(token.RefreshToken)
		if err != nil {
			return nil, err
		}

		tkr := uiRes{
			code: http.StatusCreated,
			html: user,
			cookies: []*http.Cookie{
				{
					Name:     accessTokenKey,
					Value:    token.AccessToken,
					Path:     "/",
					HttpOnly: true,
					Expires:  accessExp,
				},
				{
					Name:     refreshTokenKey,
					Value:    token.RefreshToken,
					Path:     domainsAPIEndpoint,
					HttpOnly: true,
					Expires:  refreshExp,
				},
			},
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
			return nil, err
		}

		accessExp, err := extractTokenExpiry(token.AccessToken)
		if err != nil {
			return nil, err
		}
		refreshExp, err := extractTokenExpiry(token.RefreshToken)
		if err != nil {
			return nil, err
		}

		tkr := uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": req.ref},
			cookies: []*http.Cookie{
				{
					Name:     accessTokenKey,
					Value:    token.AccessToken,
					Path:     "/",
					HttpOnly: true,
					Expires:  accessExp,
				},
				{
					Name:     refreshTokenKey,
					Value:    token.RefreshToken,
					Path:     tokenRefreshAPIEndpoint,
					HttpOnly: true,
					Expires:  refreshExp,
				},
				{
					Name:     refreshTokenKey,
					Value:    token.RefreshToken,
					Path:     domainsAPIEndpoint,
					HttpOnly: true,
					Expires:  refreshExp,
				},
			},
		}

		return tkr, nil
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
			code: http.StatusCreated,
		}, nil
	}
}

func createUsersEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(createUsersReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.CreateUsers(req.token, req.users...); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusCreated,
		}, nil
	}
}

func listUsersEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(listEntityReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListUsers(req.token, req.status, req.page, req.limit)
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

		if err := svc.UpdateUser(req.token, user); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
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
		if err := svc.UpdateUserTags(req.token, user); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
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
		if err := svc.UpdateUserIdentity(req.token, user); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
		}, nil
	}
}

func updateUserRoleEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserRoleReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		user := sdk.User{
			ID:   req.UserID,
			Role: req.Role,
		}

		if err := svc.UpdateUserRole(req.token, user); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": usersAPIEndpoint + "/" + req.UserID},
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
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": usersAPIEndpoint},
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
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": usersAPIEndpoint},
		}, nil
	}
}

func AddMemberToChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(addUserToChannelReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		userRelation := sdk.UsersRelationRequest{
			Relation: req.Relation,
			UserIDs:  []string{req.UserID},
		}

		if err := svc.AddUserToChannel(req.token, req.ChannelID, userRelation); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": channelsAPIEndpoint + "/" + req.ChannelID + usersAPIEndpoint},
		}, nil
	}
}

func RemoveMemberFromChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(addUserToChannelReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		userRelation := sdk.UsersRelationRequest{
			Relation: req.Relation,
			UserIDs:  []string{req.UserID},
		}

		if err := svc.RemoveUserFromChannel(req.token, req.ChannelID, userRelation); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": channelsAPIEndpoint + "/" + req.ChannelID + usersAPIEndpoint},
		}, nil
	}
}

func assignGroupEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(assignReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		userRelation := sdk.UsersRelationRequest{
			Relation: req.Relation,
			UserIDs:  []string{req.UserID},
		}

		if err := svc.Assign(req.token, req.GroupID, userRelation); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": groupsAPIEndpoint + "/" + req.GroupID + usersAPIEndpoint},
		}, nil
	}
}

func unassignGroupEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(assignReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		userRelation := sdk.UsersRelationRequest{
			Relation: req.Relation,
			UserIDs:  []string{req.UserID},
		}

		if err := svc.Unassign(req.token, req.GroupID, userRelation); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": groupsAPIEndpoint + "/" + req.GroupID + usersAPIEndpoint},
		}, nil
	}
}

func createThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(createThingReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.CreateThing(req.Thing, req.token); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusCreated,
		}, nil
	}
}

func createThingsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(createThingsReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.CreateThings(req.token, req.things...); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusCreated,
		}, nil
	}
}

func listThingsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(listEntityReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListThings(req.token, req.status, req.page, req.limit)
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

		if err := svc.UpdateThing(req.token, uth); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
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
		if err := svc.UpdateThingTags(req.token, thing); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
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
			code: http.StatusOK,
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
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": thingsAPIEndpoint},
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
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": thingsAPIEndpoint},
		}, nil
	}
}

func listThingMembersEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(listEntityByIDReq)

		res, err := svc.ListThingUsers(req.token, req.id, req.relation, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
			code: http.StatusOK,
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

func connectChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(connectThingReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.ConnectThing(req.ThingID, req.ChanID, req.token); err != nil {
			return nil, err
		}

		var ret uiRes

		switch req.Item {
		case thingsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": thingsAPIEndpoint + "/" + req.ThingID + channelsAPIEndpoint},
			}
		case channelsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": channelsAPIEndpoint + "/" + req.ChanID + thingsAPIEndpoint},
			}
		}

		return ret, nil
	}
}

func disconnectChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(connectThingReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.DisconnectThing(req.ThingID, req.ChanID, req.token); err != nil {
			return nil, err
		}

		var ret uiRes

		switch req.Item {
		case thingsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": thingsAPIEndpoint + "/" + req.ThingID + channelsAPIEndpoint},
			}
		case channelsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": channelsAPIEndpoint + "/" + req.ChanID + thingsAPIEndpoint},
			}
		}

		return ret, nil
	}
}

func createChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(createChannelReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.CreateChannel(req.Channel, req.token); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusCreated,
		}, nil
	}
}

func createChannelsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(createChannelsReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.CreateChannels(req.token, req.Channels...); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusCreated,
		}, nil
	}
}

func listChannelsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(listEntityReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListChannels(req.token, req.status, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
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

		if err := svc.UpdateChannel(req.token, uch); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
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
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": channelsAPIEndpoint},
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
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": channelsAPIEndpoint},
		}, nil
	}
}

func ListChannelMembersEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(listEntityByIDReq)

		res, err := svc.ListChannelUsers(req.token, req.id, req.relation, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
			code: http.StatusOK,
		}, nil
	}
}

func addGroupToChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(addUserGroupToChannelReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		groupRelation := sdk.UserGroupsRequest{
			UserGroupIDs: []string{req.GroupID},
		}

		if err := svc.AddUserGroupToChannel(req.token, req.ChannelID, groupRelation); err != nil {
			return nil, err
		}

		var ret uiRes

		switch req.Item {
		case groupsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": groupsAPIEndpoint + "/" + req.GroupID + channelsAPIEndpoint},
			}
		case channelsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": channelsAPIEndpoint + "/" + req.ChannelID + groupsAPIEndpoint},
			}
		}

		return ret, nil
	}
}

func removeGroupFromChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(addUserGroupToChannelReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		groupRelation := sdk.UserGroupsRequest{
			UserGroupIDs: []string{req.GroupID},
		}

		if err := svc.RemoveUserGroupFromChannel(req.token, req.ChannelID, groupRelation); err != nil {
			return nil, err
		}

		var ret uiRes

		switch req.Item {
		case groupsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": groupsAPIEndpoint + "/" + req.GroupID + channelsAPIEndpoint},
			}
		case channelsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": channelsAPIEndpoint + "/" + req.ChannelID + groupsAPIEndpoint},
			}
		}

		return ret, nil
	}
}

func ListChannelGroupsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(listEntityByIDReq)

		res, err := svc.ListChannelUserGroups(req.token, req.id, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
			code: http.StatusOK,
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
			code: http.StatusCreated,
		}, nil
	}
}

func createGroupsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(createGroupsReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.CreateGroups(req.token, req.Groups...); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusCreated,
		}, nil
	}
}

func listGroupMembersEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(listEntityByIDReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListGroupUsers(req.token, req.id, req.relation, req.page, req.limit)
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

		if err := svc.UpdateGroup(req.token, ugr); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
		}, nil
	}
}

func listGroupsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(listEntityReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListGroups(req.token, req.status, req.page, req.limit)
		if err != nil {
			return nil, err
		}
		return uiRes{
			code: http.StatusOK,
			html: res,
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
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": groupsAPIEndpoint},
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
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": groupsAPIEndpoint},
		}, nil
	}
}

func listGroupChannelsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(listEntityByIDReq)

		res, err := svc.ListUserGroupChannels(req.token, req.id, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
			code: http.StatusOK,
		}, nil
	}
}

func publishMessageEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(publishReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.Publish(req.token, req.ChanID, req.ThingKey, req.BaseUnit, req.Name, req.Unit, req.BaseTime, req.Value); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": "/messages?thing=" + req.ThingKey + "&channel=" + req.ChanID},
		}, nil
	}
}

func readMessagesEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(readMessagesReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ReadMessages(req.token, req.ChanID, req.ThingKey, req.Page, req.Limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
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
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": bootstrapAPIEndpoint},
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
			code: http.StatusOK,
		}, nil
	}
}

func deleteBootstrapEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(deleteBootstrapReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.DeleteBootstrap(req.token, req.id); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": bootstrapAPIEndpoint},
		}, nil
	}
}

func updateBootstrapStateEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(updateBootstrapStateReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		cfg := sdk.BootstrapConfig{
			ThingID: req.id,
			State:   req.State,
		}
		if err := svc.UpdateBootstrapState(req.token, cfg); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": bootstrapAPIEndpoint + "/" + req.id},
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
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": bootstrapAPIEndpoint + "/" + req.id},
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
			code: http.StatusOK,
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

func getEntitiesEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(getEntitiesReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.GetEntities(req.token, req.Item, req.Name, req.DomainID, req.Permission, req.Page, req.Limit)
		if err != nil {
			return nil, err
		}
		return uiRes{
			html:    res,
			code:    http.StatusOK,
			headers: map[string]string{"Content-Type": jsonContentType},
		}, nil
	}
}

func errorPageEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(errorReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ErrorPage(req.err)
		if err != nil {
			return nil, err
		}
		return uiRes{
			html: res,
			code: http.StatusOK,
		}, nil
	}
}

func domainLoginEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(domainLoginReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		token, err := svc.DomainLogin(
			sdk.Login{
				DomainID: req.DomainID,
			},
			req.token,
		)
		if err != nil {
			return nil, err
		}

		accessExp, err := extractTokenExpiry(token.AccessToken)
		if err != nil {
			return nil, err
		}
		refreshExp, err := extractTokenExpiry(token.RefreshToken)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusSeeOther,
			cookies: []*http.Cookie{
				{
					Name:     accessTokenKey,
					Value:    token.AccessToken,
					Path:     "/",
					HttpOnly: true,
					Expires:  accessExp,
				},
				{
					Name:     refreshTokenKey,
					Value:    token.RefreshToken,
					Path:     domainsAPIEndpoint,
					HttpOnly: true,
					Expires:  refreshExp,
				},
				{
					Name:     refreshTokenKey,
					Value:    token.RefreshToken,
					Path:     tokenRefreshAPIEndpoint,
					HttpOnly: true,
					Expires:  refreshExp,
				},
			},
			headers: map[string]string{"Location": "/?domain=" + req.DomainID},
		}, nil
	}
}

func listDomainsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(listEntityReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListDomains(req.token, req.status, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func createDomainEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(createDomainReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		domain := sdk.Domain{
			Name:     req.Name,
			Metadata: req.Metadata,
			Tags:     req.Tags,
			Alias:    req.Alias,
		}

		if err := svc.CreateDomain(req.token, domain); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": domainsAPIEndpoint},
		}, nil
	}
}

func updateDomainEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateDomainReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		domain := sdk.Domain{
			ID:       req.DomainID,
			Name:     req.Name,
			Metadata: req.Metadata,
			Tags:     req.Tags,
			Alias:    req.Alias,
		}

		if err := svc.UpdateDomain(req.token, domain); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
		}, nil
	}
}

func updateDomainTagsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateDomainTagsReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		domain := sdk.Domain{
			ID:   req.DomainID,
			Tags: req.Tags,
		}

		if err := svc.UpdateDomain(req.token, domain); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
		}, nil
	}
}

func domainEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(listEntityByIDReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.Domain(req.token, req.id)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func enableDomainEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateDomainStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.EnableDomain(req.token, req.DomainID); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": domainsAPIEndpoint},
		}, nil
	}
}

func disableDomainEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateDomainStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.DisableDomain(req.token, req.DomainID); err != nil {
			return nil, err
		}

		cookies := []*http.Cookie{
			{
				Name:     accessTokenKey,
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
			},
			{
				Name:     refreshTokenKey,
				Value:    "",
				Path:     tokenRefreshAPIEndpoint,
				MaxAge:   -1,
				HttpOnly: true,
			},
			{
				Name:     refreshTokenKey,
				Value:    "",
				Path:     domainsAPIEndpoint,
				MaxAge:   -1,
				HttpOnly: true,
			},
		}

		return uiRes{
			code:    http.StatusSeeOther,
			cookies: cookies,
			headers: map[string]string{"Location": loginAPIEndpoint},
		}, nil
	}
}

func assignMemberEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(assignMemberReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		relation := sdk.UsersRelationRequest{
			Relation: req.Relation,
			UserIDs:  []string{req.UserID},
		}

		if err := svc.AssignMember(req.token, req.DomainID, relation); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": domainsAPIEndpoint + "/" + req.DomainID + "/members"},
		}, nil
	}
}

func unassignMemberEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(assignMemberReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		relation := sdk.UsersRelationRequest{
			Relation: req.Relation,
			UserIDs:  []string{req.UserID},
		}

		if err := svc.UnassignMember(req.token, req.DomainID, relation); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": domainsAPIEndpoint + "/" + req.DomainID + "/members"},
		}, nil
	}
}

func viewMemberEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(viewMemberReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ViewMember(req.token, req.UserIdentity)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func listMembersEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(listEntityByIDReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.Members(req.token, req.id, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func shareThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(shareThingReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		userRelation := sdk.UsersRelationRequest{
			Relation: req.Relation,
			UserIDs:  []string{req.UserID},
		}

		if err := svc.ShareThing(req.token, req.ThingID, userRelation); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": thingsAPIEndpoint + "/" + req.ThingID + usersAPIEndpoint},
		}, nil
	}
}

func unshareThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(shareThingReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		userRelation := sdk.UsersRelationRequest{
			Relation: req.Relation,
			UserIDs:  []string{req.UserID},
		}

		if err := svc.UnshareThing(req.token, req.ThingID, userRelation); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": thingsAPIEndpoint + "/" + req.ThingID + usersAPIEndpoint},
		}, nil
	}
}

func sendInvitationEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(sendInvitationReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		invitation := sdk.Invitation{
			DomainID: req.DomainID,
			UserID:   req.UserID,
			Relation: req.Relation,
		}

		if err := svc.SendInvitation(req.token, invitation); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
		}, nil
	}
}

func listInvitationsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(listInvitationsReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.Invitations(req.token, req.DomainID, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func acceptInvitationEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(acceptInvitationReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.AcceptInvitation(req.token, req.DomainID); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": "/domains"},
		}, nil
	}
}

func deleteInvitationEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(deleteInvitationReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.DeleteInvitation(req.token, req.UserID, req.DomainID); err != nil {
			return nil, err
		}

		if req.domain == "" {
			return uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": "/invitations"},
			}, nil
		} else {
			return uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": domainsAPIEndpoint + "/" + req.DomainID + "/invitations"},
			}, nil
		}
	}
}

func extractTokenExpiry(token string) (time.Time, error) {
	jwtToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		return time.Time{}, err
	}
	var expTime time.Time
	if claims, ok := jwtToken.Claims.(jwt.MapClaims); ok {
		expUnix := int64(claims["exp"].(float64))
		expTime = time.Unix(expUnix, 0)
	}
	return expTime, nil
}
