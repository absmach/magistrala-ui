// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
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

func createThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createThingReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		th := sdk.Thing{
			Key:      req.Key,
			Name:     req.Name,
			Metadata: req.Metadata,
		}
		res, err := svc.CreateThings(ctx, req.token, th)
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

func listThingsEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listThingsReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.ListThings(ctx, req.token)
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

func removeThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewResourceReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.RemoveThing(ctx, req.token, req.id)
		if err != nil {
			return nil, err
		}
		return uiRes{
			html:    res,
			headers: map[string]string{"location": redirectURL + "things"},
			code:    http.StatusPermanentRedirect,
		}, err
	}
}

func createChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createChannelReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		ch := sdk.Channel{
			ID:       req.ID,
			Name:     req.Name,
			Metadata: req.Metadata,
		}
		res, err := svc.CreateChannels(ctx, req.token, ch)
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
			html: res,
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
			ID:       req.id,
			Name:     req.Name,
			Metadata: req.Metadata,
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

func removeChannelEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewResourceReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.RemoveChannel(ctx, req.token, req.id)
		if err != nil {
			return nil, err
		}
		return uiRes{
			html:    res,
			headers: map[string]string{"location": redirectURL + "channels"},
			code:    http.StatusPermanentRedirect,
		}, err
	}
}

func connectThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		cr := request.(connectThingReq)

		if err := cr.validate(); err != nil {
			return nil, err
		}

		res, err := svc.Connect(ctx, cr.token, []string{cr.ChanID}, []string{cr.ThingID})
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

		res, err := svc.ListThingByChannel(ctx, req.token, req.id)
		if err != nil {
			return nil, err
		}
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

func disconnectThingEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		dcr := request.(disconnectThingReq)

		if err := dcr.validate(); err != nil {
			return nil, err
		}

		res, err := svc.DisconnectThing(ctx, dcr.token, []string{dcr.ChanID}, []string{dcr.ThingID})
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

		res, err := svc.DisconnectChannel(ctx, dcr.token, []string{dcr.ThingID}, []string{dcr.ChanID})
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
		cgr := request.(createGroupsReq)

		if err := cgr.validate(); err != nil {
			return nil, err
		}

		gr := sdk.Group{
			Name:        cgr.Name,
			Description: cgr.Description,
			ParentID:    cgr.ParentID,
			Metadata:    cgr.Metadata,
		}

		res, err := svc.CreateGroups(ctx, cgr.token, gr)
		if err != nil {
			return nil, err
		}

		return uiRes{
			html: res,
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

func assignEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(assignReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.Assign(ctx, req.token, req.groupID, req.Type, req.Member)
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

		res, err := svc.Unassign(ctx, req.token, req.groupID, req.Member)
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
			ID:       req.id,
			Name:     req.Name,
			Metadata: req.Metadata,
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

func removeGroupEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewResourceReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.RemoveGroup(ctx, req.token, req.id)
		if err != nil {
			return nil, err
		}
		return uiRes{
			html:    res,
			headers: map[string]string{"location": redirectURL + "groups"},
			code:    http.StatusPermanentRedirect,
		}, err
	}
}

func sendMessageEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(sendMessageReq)
		if err := req.validate(); err != nil {
			return nil, err
		}
		res, err := svc.SendMessage(ctx, req.token)
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
		res, err := svc.Publish(ctx, req.thingKey, req.msg)
		if err != nil {
			return nil, err
		}

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

func tokenEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(tokenReq)
		token, err := svc.Token(ctx, req.username, req.password)
		if err != nil {
			return nil, errors.Wrap(errUnauthorized, err)
		}
		tkr := uiRes{
			code:    http.StatusFound,
			headers: map[string]string{"Set-Cookie": fmt.Sprintf("token=%s;", token), "Location": "/"},
		}

		return tkr, nil
	}
}

func logoutEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		res, err := svc.Logout(ctx)
		return uiRes{
			code:    http.StatusFound,
			html:    res,
			headers: map[string]string{"Set-Cookie": "token=;Max-Age=0;", "Location": "/login"},
		}, err
	}
}

func createUserEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createUserReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		user := sdk.User{
			Email:    req.Email,
			Groups:   req.Groups,
			Password: req.Password,
			Metadata: req.Metadata,
		}
		res, err := svc.CreateUser(ctx, req.token, user)
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
			user := sdk.User{
				Email:    req.Emails[i],
				Password: req.Passwords[i],
			}
			users = append(users, user)
		}
		res, err := svc.CreateUser(ctx, req.token, users...)
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

func updateUserEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		user := sdk.User{
			ID:       req.id,
			Email:    req.Email,
			Groups:   req.Group,
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

func updateUserPasswordEndpoint(svc ui.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateUserPasswordReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		res, err := svc.UpdateUserPassword(ctx, req.token, req.id, req.OldPass, req.NewPass)
		if err != nil {
			return nil, err
		}
		return uiRes{
			html: res,
		}, err
	}
}
