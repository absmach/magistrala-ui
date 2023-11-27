// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"

	"github.com/absmach/magistrala-ui/ui"
	sdk "github.com/absmach/magistrala/pkg/sdk/go"
	"github.com/go-kit/kit/endpoint"
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
		credentials := sdk.Credentials{
			Identity: req.Identity,
			Secret:   req.Secret,
		}
		user := sdk.User{
			Credentials: credentials,
		}

		token, err := svc.Token(user)
		if err != nil {
			return nil, err
		}

		cookies := []*http.Cookie{
			{
				Name:     accessTokenKey,
				Value:    token.AccessToken,
				Path:     "/",
				HttpOnly: true,
			},
			{
				Name:     refreshTokenKey,
				Value:    token.RefreshToken,
				Path:     tokenRefreshAPIEndpoint,
				HttpOnly: true,
			},
		}

		tkr := uiRes{
			code:    http.StatusCreated,
			cookies: cookies,
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

		cookies := []*http.Cookie{
			{
				Name:     accessTokenKey,
				Value:    token.AccessToken,
				Path:     "/",
				HttpOnly: true,
			},
			{
				Name:     refreshTokenKey,
				Value:    token.RefreshToken,
				Path:     tokenRefreshAPIEndpoint,
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
		if err := svc.UpdateUserTags(req.token, req.id, user); err != nil {
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
		if err := svc.UpdateUserIdentity(req.token, req.id, user); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
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

func listUserGroupsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(listEntityByIDReq)

		res, err := svc.ListUserGroups(req.token, req.id, req.relation, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
			code: http.StatusOK,
		}, nil
	}
}

func listUserThingsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(listEntityByIDReq)

		res, err := svc.ListUserThings(req.token, req.id, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
			code: http.StatusOK,
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

		var ret uiRes

		switch req.Item {
		case usersItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": usersAPIEndpoint + "/" + req.UserID + thingsAPIEndpoint},
			}
		case thingsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": thingsAPIEndpoint + "/" + req.ThingID + usersAPIEndpoint},
			}
		}

		return ret, nil
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

		var ret uiRes

		switch req.Item {
		case usersItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": usersAPIEndpoint + "/" + req.UserID + thingsAPIEndpoint},
			}
		case thingsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": thingsAPIEndpoint + "/" + req.ThingID + usersAPIEndpoint},
			}
		}

		return ret, nil
	}
}

func listUserChannelsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(listEntityByIDReq)

		res, err := svc.ListUserChannels(req.token, req.id, req.relation, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
			code: http.StatusOK,
		}, nil
	}
}

func AddChannelToUserEndpoint(svc ui.Service) endpoint.Endpoint {
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

		var ret uiRes

		switch req.Item {
		case usersItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": usersAPIEndpoint + "/" + req.UserID + channelsAPIEndpoint},
			}
		case channelsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": channelsAPIEndpoint + "/" + req.ChannelID + usersAPIEndpoint},
			}
		}

		return ret, nil
	}
}

func RemoveChannelFromUserEndpoint(svc ui.Service) endpoint.Endpoint {
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

		var ret uiRes

		switch req.Item {
		case usersItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": usersAPIEndpoint + "/" + req.UserID + channelsAPIEndpoint},
			}
		case channelsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": channelsAPIEndpoint + "/" + req.ChannelID + usersAPIEndpoint},
			}
		}

		return ret, nil
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

		var ret uiRes

		switch req.Item {
		case usersItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": usersAPIEndpoint + "/" + req.UserID + groupsAPIEndpoint},
			}
		case groupsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": groupsAPIEndpoint + "/" + req.GroupID + usersAPIEndpoint},
			}
		}

		return ret, nil
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

		var ret uiRes

		switch req.Item {
		case usersItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": usersAPIEndpoint + "/" + req.UserID + groupsAPIEndpoint},
			}
		case groupsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": groupsAPIEndpoint + "/" + req.GroupID + usersAPIEndpoint},
			}
		}

		return ret, nil
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
		if err := svc.UpdateThingTags(req.token, req.id, thing); err != nil {
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

func listThingUsersEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(listEntityByIDReq)

		res, err := svc.ListThingUsers(req.token, req.id, req.page, req.limit)
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
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": channelsAPIEndpoint},
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
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": channelsAPIEndpoint},
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
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": channelsAPIEndpoint + "/" + req.id},
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

func ListChannelUsersEndpoint(svc ui.Service) endpoint.Endpoint {
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

func addUserGroupToChannelEndpoint(svc ui.Service) endpoint.Endpoint {
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

func removeUserGroupFromChannelEndpoint(svc ui.Service) endpoint.Endpoint {
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

func ListChannelUserGroupsEndpoint(svc ui.Service) endpoint.Endpoint {
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
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": groupsAPIEndpoint},
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
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": groupsAPIEndpoint},
		}, nil
	}
}

func listGroupUsersEndpoint(svc ui.Service) endpoint.Endpoint {
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

		if err := svc.UpdateGroup(req.token, req.id, ugr); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": groupsAPIEndpoint + "/" + req.id},
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

func listParentsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(listEntityByIDReq)

		res, err := svc.ListParents(req.token, req.id, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
			code: http.StatusOK,
		}, nil
	}
}

func listChildrenEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(listEntityByIDReq)

		res, err := svc.ListChildren(req.token, req.id, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
			code: http.StatusOK,
		}, nil
	}
}

func listUserGroupChannelsEndpoint(svc ui.Service) endpoint.Endpoint {
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

		if err := svc.Publish(req.token, req.thingKey, req.Msg); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": channelsAPIEndpoint + "/" + req.Msg.Channel + thingsAPIEndpoint},
		}, nil
	}
}

func readMessageEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(readMessageReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.ReadMessage(req.token, req.ChanID, req.ThingKey, req.Page, req.Limit)
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
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": bootstrapAPIEndpoint + "/" + req.thingID},
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

		res, err := svc.GetEntities(req.token, req.Item, req.Name, req.Page, req.Limit)
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
