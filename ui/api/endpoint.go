// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/absmach/magistrala-ui/ui"
	"github.com/go-kit/kit/endpoint"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/securecookie"
	"golang.org/x/sync/errgroup"
)

func indexEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(indexReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.Index(req.Session)
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

func registerUserEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(registerUserReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		token, err := svc.RegisterUser(req.User)
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
			code: http.StatusOK,
			cookies: []*http.Cookie{
				{
					Name:     accessTokenKey,
					Value:    token.AccessToken,
					Path:     prefix,
					HttpOnly: true,
					Expires:  accessExp,
				},
				{
					Name:     refreshTokenKey,
					Value:    token.RefreshToken,
					Path:     prefix,
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

func logoutEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, _ interface{}) (interface{}, error) {
		if err := svc.Logout(); err != nil {
			return nil, err
		}

		cookies := []*http.Cookie{
			{
				Name:   sessionDetailsKey,
				Value:  "",
				Path:   prefix,
				MaxAge: -1,
			},
		}
		return uiRes{
			code:    http.StatusOK,
			cookies: cookies,
		}, nil
	}
}

func passwordResetRequestEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(passwordResetRequestReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.PasswordResetRequest(req.email); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s", prefix, loginAPIEndpoint)},
		}, nil
	}
}

func passwordResetEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(passwordResetReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.PasswordReset(req.token, req.password, req.confirmPassword); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s", prefix, loginAPIEndpoint)},
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

		res, err := svc.PasswordUpdate(req.Session)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func updatePasswordEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserPasswordReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.UpdatePassword(req.token, req.oldPass, req.newPass); err != nil {
			return nil, err
		}

		cookies := []*http.Cookie{
			{
				Name:   sessionDetailsKey,
				Value:  "",
				Path:   prefix,
				MaxAge: -1,
			},
		}

		return uiRes{
			code:    http.StatusSeeOther,
			cookies: cookies,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s", prefix, loginAPIEndpoint)},
		}, nil
	}
}

func tokenEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(tokenReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		token, err := svc.Token(req.Login)
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
			code: http.StatusOK,
			cookies: []*http.Cookie{
				{
					Name:     accessTokenKey,
					Value:    token.AccessToken,
					Path:     prefix,
					HttpOnly: true,
					Expires:  accessExp,
				},
				{
					Name:     refreshTokenKey,
					Value:    token.RefreshToken,
					Path:     prefix,
					HttpOnly: true,
					Expires:  refreshExp,
				},
			},
		}

		return tkr, nil
	}
}

func secureTokenEndpoint(svc ui.Service, s *securecookie.SecureCookie, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(secureTokenReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		sessionDetails, err := svc.Session(req.Session)
		if err != nil {
			return nil, err
		}

		sessionDetails.Token = req.Token

		session, err := json.Marshal(sessionDetails)
		if err != nil {
			return nil, err
		}
		secureSessionDetails, err := s.Encode(sessionDetailsKey, string(session))
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusSeeOther,
			cookies: []*http.Cookie{
				{
					Name:  sessionDetailsKey,
					Value: secureSessionDetails,
					Path:  prefix,
				},
				{
					Name:     accessTokenKey,
					Value:    "",
					Path:     prefix,
					MaxAge:   -1,
					HttpOnly: true,
				},
				{
					Name:     refreshTokenKey,
					Value:    "",
					Path:     prefix,
					MaxAge:   -1,
					HttpOnly: true,
				},
			},
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s", prefix, domainsAPIEndpoint)},
		}, nil
	}
}

func refreshTokenEndpoint(svc ui.Service, s *securecookie.SecureCookie, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(refreshTokenReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		token, err := svc.RefreshToken(req.RefreshToken)
		if err != nil {
			return nil, err
		}

		req.Session.Token = token
		session, err := json.Marshal(req.Session)
		if err != nil {
			return nil, err
		}
		secureSessionDetails, err := s.Encode(sessionDetailsKey, string(session))
		if err != nil {
			return nil, err
		}

		tkr := uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": req.ref},
			cookies: []*http.Cookie{
				{
					Name:  sessionDetailsKey,
					Value: secureSessionDetails,
					Path:  prefix,
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

		res, err := svc.ListUsers(req.Session, req.status, req.page, req.limit)
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

		res, err := svc.ViewUser(req.Session, req.id)
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

		if err := svc.UpdateUser(req.token, req.User); err != nil {
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

		if err := svc.UpdateUserTags(req.token, req.User); err != nil {
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

		if err := svc.UpdateUserIdentity(req.token, req.User); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
		}, nil
	}
}

func updateUserRoleEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserRoleReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.UpdateUserRole(req.token, req.User); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s/%s", prefix, usersAPIEndpoint, req.ID)},
		}, nil
	}
}

func enableUserEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.EnableUser(req.token, req.id); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s", prefix, usersAPIEndpoint)},
		}, nil
	}
}

func disableUserEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.DisableUser(req.token, req.id); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s", prefix, usersAPIEndpoint)},
		}, nil
	}
}

func AddMemberToChannelEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(addUserToChannelReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.AddUserToChannel(req.token, req.ChannelID, req.UsersRelationRequest); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s/%s/%s", prefix, channelsAPIEndpoint, req.ChannelID, usersAPIEndpoint)},
		}, nil
	}
}

func RemoveMemberFromChannelEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(addUserToChannelReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.RemoveUserFromChannel(req.token, req.ChannelID, req.UsersRelationRequest); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s/%s/%s", prefix, channelsAPIEndpoint, req.ChannelID, usersAPIEndpoint)},
		}, nil
	}
}

func assignGroupEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(assignReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.Assign(req.token, req.groupID, req.UsersRelationRequest); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s/%s/%s", prefix, groupsAPIEndpoint, req.groupID, usersAPIEndpoint)},
		}, nil
	}
}

func unassignGroupEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(assignReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.Unassign(req.token, req.groupID, req.UsersRelationRequest); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s/%s/%s", prefix, groupsAPIEndpoint, req.groupID, usersAPIEndpoint)},
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

		res, err := svc.ListThings(req.Session, req.status, req.page, req.limit)
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

		res, err := svc.ViewThing(req.Session, req.id)
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

		if err := svc.UpdateThing(req.token, req.Thing); err != nil {
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

		if err := svc.UpdateThingTags(req.token, req.Thing); err != nil {
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

		if err := svc.UpdateThingSecret(req.token, req.ID, req.Credentials.Secret); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
		}, nil
	}
}

func enableThingEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateThingStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.EnableThing(req.token, req.id); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s", prefix, thingsAPIEndpoint)},
		}, nil
	}
}

func disableThingEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateThingStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.DisableThing(req.token, req.id); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s", prefix, thingsAPIEndpoint)},
		}, nil
	}
}

func listThingMembersEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(listEntityByIDReq)

		res, err := svc.ListThingUsers(req.Session, req.id, req.relation, req.page, req.limit)
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

		res, err := svc.ListChannelsByThing(req.Session, req.id, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func connectChannelEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(connectThingReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.ConnectThing(req.thingID, req.channelID, req.token); err != nil {
			return nil, err
		}

		var ret uiRes

		switch req.item {
		case thingsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": fmt.Sprintf("%s/%s/%s/%s", prefix, thingsAPIEndpoint, req.thingID, channelsAPIEndpoint)},
			}
		case channelsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": fmt.Sprintf("%s/%s/%s/%s", prefix, channelsAPIEndpoint, req.channelID, thingsAPIEndpoint)},
			}
		}

		return ret, nil
	}
}

func disconnectChannelEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(connectThingReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.DisconnectThing(req.thingID, req.channelID, req.token); err != nil {
			return nil, err
		}

		var ret uiRes

		switch req.item {
		case thingsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": fmt.Sprintf("%s/%s/%s/%s", prefix, thingsAPIEndpoint, req.thingID, channelsAPIEndpoint)},
			}
		case channelsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": fmt.Sprintf("%s/%s/%s/%s", prefix, channelsAPIEndpoint, req.channelID, thingsAPIEndpoint)},
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

		res, err := svc.ListChannels(req.Session, req.status, req.page, req.limit)
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

		res, err := svc.ViewChannel(req.Session, req.id)
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

		if err := svc.UpdateChannel(req.token, req.Channel); err != nil {
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

		res, err := svc.ListThingsByChannel(req.Session, req.id, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func enableChannelEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateChannelStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.EnableChannel(req.token, req.id); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s", prefix, channelsAPIEndpoint)},
		}, nil
	}
}

func disableChannelEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateChannelStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.DisableChannel(req.token, req.id); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s", prefix, channelsAPIEndpoint)},
		}, nil
	}
}

func ListChannelMembersEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(listEntityByIDReq)

		res, err := svc.ListChannelUsers(req.Session, req.id, req.relation, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
			code: http.StatusOK,
		}, nil
	}
}

func addGroupToChannelEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(addUserGroupToChannelReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.AddUserGroupToChannel(req.token, req.channelID, req.UserGroupsRequest); err != nil {
			return nil, err
		}

		var ret uiRes

		switch req.item {
		case groupsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": fmt.Sprintf("%s/%s/%s/%s", prefix, groupsAPIEndpoint, req.UserGroupIDs[0], channelsAPIEndpoint)},
			}
		case channelsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": fmt.Sprintf("%s/%s/%s/%s", prefix, channelsAPIEndpoint, req.channelID, groupsAPIEndpoint)},
			}
		}

		return ret, nil
	}
}

func removeGroupFromChannelEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(addUserGroupToChannelReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.RemoveUserGroupFromChannel(req.token, req.channelID, req.UserGroupsRequest); err != nil {
			return nil, err
		}

		var ret uiRes

		switch req.item {
		case groupsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": fmt.Sprintf("%s/%s/%s/%s", prefix, groupsAPIEndpoint, req.UserGroupIDs[0], channelsAPIEndpoint)},
			}
		case channelsItem:
			ret = uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": fmt.Sprintf("%s/%s/%s/%s", prefix, channelsAPIEndpoint, req.channelID, groupsAPIEndpoint)},
			}
		}

		return ret, nil
	}
}

func ListChannelGroupsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(listEntityByIDReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListChannelUserGroups(req.Session, req.id, req.page, req.limit)
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

		res, err := svc.ListGroupUsers(req.Session, req.id, req.relation, req.page, req.limit)
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

		res, err := svc.ViewGroup(req.Session, req.id)
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

		if err := svc.UpdateGroup(req.token, req.Group); err != nil {
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

		res, err := svc.ListGroups(req.Session, req.status, req.page, req.limit)
		if err != nil {
			return nil, err
		}
		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func enableGroupEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateGroupStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.EnableGroup(req.token, req.id); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s", prefix, groupsAPIEndpoint)},
		}, nil
	}
}

func disableGroupEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateGroupStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.DisableGroup(req.token, req.id); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s", prefix, groupsAPIEndpoint)},
		}, nil
	}
}

func listGroupChannelsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(listEntityByIDReq)

		res, err := svc.ListUserGroupChannels(req.Session, req.id, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
			code: http.StatusOK,
		}, nil
	}
}

func publishMessageEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(publishReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.Publish(req.channelID, req.thingKey, req.Message); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/messages?thing=%s&channel=%s", prefix, req.thingKey, req.channelID)},
		}, nil
	}
}

func readMessagesEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(readMessagesReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ReadMessages(req.Session, req.channelID, req.thingKey, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func createBootstrap(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(createBootstrapReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.CreateBootstrap(req.token, req.BootstrapConfig); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s", prefix, bootstrapAPIEndpoint)},
		}, nil
	}
}

func listBootstrap(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(listEntityReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListBootstrap(req.Session, req.page, req.limit)
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

		if err := svc.UpdateBootstrap(req.token, req.BootstrapConfig); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
		}, nil
	}
}

func deleteBootstrapEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
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
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s", prefix, bootstrapAPIEndpoint)},
		}, nil
	}
}

func updateBootstrapStateEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(updateBootstrapStateReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.UpdateBootstrapState(req.token, req.BootstrapConfig); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s/%s", prefix, bootstrapAPIEndpoint, req.ThingID)},
		}, nil
	}
}

func updateBootstrapConnections(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(updateBootstrapConnReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.UpdateBootstrapConnections(req.token, req.BootstrapConfig); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s/%s", prefix, bootstrapAPIEndpoint, req.ThingID)},
		}, nil
	}
}

func updateBootstrapCerts(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(updateBootstrapCertReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.UpdateBootstrapCerts(req.token, req.BootstrapConfig); err != nil {
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

		res, err := svc.ViewBootstrap(req.Session, req.id)
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
		res, err := svc.GetRemoteTerminal(req.Session, req.id)
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
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(getEntitiesReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.GetEntities(req.token, req.item, req.name, req.domainID, req.permission, req.page, req.limit)
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
	return func(_ context.Context, request interface{}) (response interface{}, err error) {
		req := request.(errorReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ErrorPage(req.err, req.pageURL)
		if err != nil {
			return nil, err
		}
		return uiRes{
			html: res,
			code: http.StatusOK,
		}, nil
	}
}

func domainLoginEndpoint(svc ui.Service, s *securecookie.SecureCookie, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(domainLoginReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		token, err := svc.DomainLogin(req.Login, req.RefreshToken)
		if err != nil {
			return nil, err
		}
		req.Domain.ID = req.DomainID
		req.AccessToken = token.AccessToken
		sessionDetails, err := svc.Session(req.Session)
		if err != nil {
			return nil, err
		}

		sessionDetails.Token = token
		session, err := json.Marshal(sessionDetails)
		if err != nil {
			return nil, err
		}
		secureSessionDetails, err := s.Encode(sessionDetailsKey, string(session))
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusSeeOther,
			cookies: []*http.Cookie{
				{
					Name:  sessionDetailsKey,
					Value: secureSessionDetails,
					Path:  prefix,
				},
			},
			headers: map[string]string{"Location": fmt.Sprintf("%s/?domain=%s", prefix, req.DomainID)},
		}, nil
	}
}

func listDomainsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(listDomainsReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListDomains(req.Session, req.status, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func createDomainEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(createDomainReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.CreateDomain(req.token, req.Domain); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s", prefix, domainsAPIEndpoint)},
		}, nil
	}
}

func updateDomainEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateDomainReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.UpdateDomain(req.token, req.Domain); err != nil {
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

		if err := svc.UpdateDomain(req.token, req.Domain); err != nil {
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

		res, err := svc.Domain(req.Session)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func enableDomainEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateDomainStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.EnableDomain(req.token, req.id); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s", prefix, domainsAPIEndpoint)},
		}, nil
	}
}

func disableDomainEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateDomainStatusReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.DisableDomain(req.token, req.id); err != nil {
			return nil, err
		}

		cookies := []*http.Cookie{
			{
				Name:     accessTokenKey,
				Value:    "",
				Path:     prefix,
				MaxAge:   -1,
				HttpOnly: true,
			},
		}

		return uiRes{
			code:    http.StatusSeeOther,
			cookies: cookies,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s", prefix, loginAPIEndpoint)},
		}, nil
	}
}

func assignMemberEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(assignMemberReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.AssignMember(req.token, req.domainID, req.UsersRelationRequest); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s/%s/members", prefix, domainsAPIEndpoint, req.domainID)},
		}, nil
	}
}

func unassignMemberEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(assignMemberReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.UnassignMember(req.token, req.domainID, req.UsersRelationRequest); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s/%s/members", prefix, domainsAPIEndpoint, req.domainID)},
		}, nil
	}
}

func viewMemberEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(viewMemberReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ViewMember(req.Session, req.userIdentity)
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

		res, err := svc.Members(req.Session, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func shareThingEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(shareThingReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.ShareThing(req.token, req.id, req.UsersRelationRequest); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s/%s/%s", prefix, thingsAPIEndpoint, req.id, usersAPIEndpoint)},
		}, nil
	}
}

func unshareThingEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(shareThingReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.UnshareThing(req.token, req.id, req.UsersRelationRequest); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s/%s/%s", prefix, thingsAPIEndpoint, req.id, usersAPIEndpoint)},
		}, nil
	}
}

func sendInvitationEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(sendInvitationReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.SendInvitation(req.token, req.Invitation); err != nil {
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

		res, err := svc.Invitations(req.Session, req.domainID, req.page, req.limit)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func acceptInvitationEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(acceptInvitationReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.AcceptInvitation(req.token, req.domainID); err != nil {
			return nil, err
		}

		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s", prefix, domainsAPIEndpoint)},
		}, nil
	}
}

func deleteInvitationEndpoint(svc ui.Service, prefix string) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(deleteInvitationReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.DeleteInvitation(req.token, req.userID, req.domainID); err != nil {
			return nil, err
		}

		if req.domain == "" {
			return uiRes{
				code:    http.StatusSeeOther,
				headers: map[string]string{"Location": fmt.Sprintf("%s/invitations", prefix)},
			}, nil
		}
		return uiRes{
			code:    http.StatusSeeOther,
			headers: map[string]string{"Location": fmt.Sprintf("%s/%s/%s/invitations", prefix, domainsAPIEndpoint, req.domainID)},
		}, nil
	}
}

func viewDashboardEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(viewDashboardReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ViewDashboard(req.Session, req.DashboardID)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func createDashboardEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(createDashboardReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		dr := ui.DashboardReq{
			Name:        req.Name,
			Description: req.Description,
			Layout:      req.Layout,
		}

		res, err := svc.CreateDashboard(req.token, dr)
		if err != nil {
			return nil, err
		}
		return uiRes{
			code:    http.StatusCreated,
			html:    res,
			headers: map[string]string{"Content-Type": jsonContentType},
		}, nil
	}
}

func listDashboardsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(listDashboardsReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListDashboards(req.token, req.page, req.limit)
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

func dashboardsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(dashboardsReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.Dashboards(req.Session)
		if err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
			html: res,
		}, nil
	}
}

func updateDashboardEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(updateDashboardReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		d := ui.DashboardReq{
			Name:        req.Name,
			Description: req.Description,
			Layout:      req.Layout,
			Metadata:    req.Metadata,
		}
		if err := svc.UpdateDashboard(req.token, req.ID, d); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusOK,
		}, nil
	}
}

func deleteDashboardEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(_ context.Context, request interface{}) (interface{}, error) {
		req := request.(deleteDashboardReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.DeleteDashboard(req.token, req.ID); err != nil {
			return nil, err
		}

		return uiRes{
			code: http.StatusNoContent,
		}, nil
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
