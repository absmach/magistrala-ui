// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

// Package ui contains the domain concept definitions needed to support
// Mainflux ui adapter service functionality.
package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"

	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/mainflux/mainflux/pkg/messaging"

	"github.com/mainflux/mainflux"
	sdk "github.com/mainflux/mainflux/pkg/sdk/go"
)

const (
	templateDir = "ui/web/template"
)

var (
	// ErrUnauthorizedAccess indicates missing or invalid credentials provided
	// when accessing a protected resource.
	ErrUnauthorizedAccess = errors.New("missing or invalid credentials provided")

	// ErrMalformedEntity indicates malformed entity specification (e.g.
	// invalid username or password).
	ErrMalformedEntity = errors.New("malformed entity specification")

	tmplFiles = []string{"header.html", "footer.html", "navbar.html"}
)

// Service specifies coap service API.
type Service interface {
	Index(ctx context.Context, token string) ([]byte, error)
	Login(ctx context.Context) ([]byte, error)
	Logout(ctx context.Context) ([]byte, error)
	Token(ctx context.Context, username, password string) (string, error)
	CreateThings(ctx context.Context, token string, things ...sdk.Thing) ([]byte, error)
	ViewThing(ctx context.Context, token, id string) ([]byte, error)
	UpdateThing(ctx context.Context, token, id string, thing sdk.Thing) ([]byte, error)
	ListThings(ctx context.Context, token string) ([]byte, error)
	RemoveThing(ctx context.Context, token, id string) ([]byte, error)
	CreateChannels(ctx context.Context, token string, channels ...sdk.Channel) ([]byte, error)
	ViewChannel(ctx context.Context, token, id string) ([]byte, error)
	UpdateChannel(ctx context.Context, token, id string, channel sdk.Channel) ([]byte, error)
	ListChannels(ctx context.Context, token string) ([]byte, error)
	RemoveChannel(ctx context.Context, token, id string) ([]byte, error)
	Connect(ctx context.Context, token string, chIDs, thIDs []string) ([]byte, error)
	ListThingByChannel(ctx context.Context, token, id string) ([]byte, error)
	ListGroupMembers(ctx context.Context, token, id string) ([]byte, error)
	ListChannelsByThing(ctx context.Context, token, id string) ([]byte, error)
	DisconnectThing(ctx context.Context, token string, chIDs, thIDs []string) ([]byte, error)
	DisconnectChannel(ctx context.Context, token string, chIDs, thIDs []string) ([]byte, error)
	CreateGroups(ctx context.Context, token string, groups ...sdk.Group) ([]byte, error)
	Assign(ctx context.Context, token, groupID, groupType string, memberIDs ...string) ([]byte, error)
	Unassign(ctx context.Context, token, groupID string, memberIDs ...string) ([]byte, error)
	ViewGroup(ctx context.Context, token, id string) ([]byte, error)
	UpdateGroup(ctx context.Context, token, id string, group sdk.Group) ([]byte, error)
	ListGroups(ctx context.Context, token string) ([]byte, error)
	RemoveGroup(ctx context.Context, token, id string) ([]byte, error)
	Publish(ctx context.Context, thingKey string, msg messaging.Message) ([]byte, error)
	SendMessage(ctx context.Context, token string) ([]byte, error)
	CreateUser(ctx context.Context, token string, user ...sdk.User) ([]byte, error)
	ViewUser(ctx context.Context, token, id string) ([]byte, error)
	UpdateUser(ctx context.Context, token, id string, user sdk.User) ([]byte, error)
	UpdateUserPassword(ctx context.Context, token, id, oldPass, newPass string) ([]byte, error)
	ListUsers(ctx context.Context, token string) ([]byte, error)
}

var _ Service = (*uiService)(nil)

type uiService struct {
	things mainflux.ThingsServiceClient
	sdk    sdk.SDK
}

// New instantiates the HTTP adapter implementation.
func New(things mainflux.ThingsServiceClient, sdk sdk.SDK) Service {
	return &uiService{
		things: things,
		sdk:    sdk,
	}
}

func parseTemplate(name string, tmpls ...string) (tpl *template.Template, err error) {
	tpl = template.New(name)
	tpl = tpl.Funcs(template.FuncMap{
		"toJSON": func(data map[string]interface{}) string {
			ret, _ := json.Marshal(data)
			return string(ret)
		},
	})

	a := append(tmplFiles, tmpls...)
	for i := range a {
		a[i] = fmt.Sprintf("%s/%s", templateDir, a[i])
	}

	tpl, err = tpl.ParseFiles(a...)
	if err != nil {
		return nil, err
	}

	return tpl, nil
}

func (gs *uiService) Index(ctx context.Context, token string) ([]byte, error) {
	tpl, err := parseTemplate("index", "index.html")
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
	}{
		"dashboard",
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "index", data); err != nil {
		println(err.Error())
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) CreateThings(ctx context.Context, token string, things ...sdk.Thing) ([]byte, error) {
	for i := range things {
		_, err := gs.sdk.CreateThing(things[i], token)
		if err != nil {
			return []byte{}, err
		}
	}

	return gs.ListThings(ctx, token)
}

func (gs *uiService) ListThings(ctx context.Context, token string) ([]byte, error) {
	tpl, err := parseTemplate("things", "things.html")
	if err != nil {
		return []byte{}, err
	}
	filter := sdk.PageMetadata{
		Offset: uint64(0),
		Total:  uint64(100),
		Limit:  uint64(100),
	}
	thsPage, err := gs.sdk.Things(token, filter)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		Things       []sdk.Thing
	}{
		"things",
		thsPage.Things,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "things", data); err != nil {
		println(err.Error())
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) ViewThing(ctx context.Context, token, id string) ([]byte, error) {
	tpl, err := parseTemplate("thing", "thing.html")
	if err != nil {
		return []byte{}, err
	}

	thing, err := gs.sdk.Thing(id, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		ID           string
		Thing        sdk.Thing
	}{
		"things",
		id,
		thing,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "thing", data); err != nil {
		println(err.Error())
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) UpdateThing(ctx context.Context, token, id string, thing sdk.Thing) ([]byte, error) {
	if err := gs.sdk.UpdateThing(thing, token); err != nil {
		return []byte{}, err
	}
	return gs.ViewThing(ctx, token, id)
}

func (gs *uiService) RemoveThing(ctx context.Context, token, id string) ([]byte, error) {
	err := gs.sdk.DeleteThing(id, token)
	if err != nil {
		return []byte{}, err
	}
	return []byte{}, nil
}

func (gs *uiService) CreateChannels(ctx context.Context, token string, channels ...sdk.Channel) ([]byte, error) {
	for i := range channels {
		_, err := gs.sdk.CreateChannel(channels[i], token)
		if err != nil {
			return []byte{}, err
		}
	}
	return gs.ListChannels(ctx, token)
}

func (gs *uiService) ViewChannel(ctx context.Context, token, id string) ([]byte, error) {
	tpl, err := parseTemplate("channel", "channel.html")
	if err != nil {
		return []byte{}, err
	}

	channel, err := gs.sdk.Channel(id, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		ID           string
		Channel      sdk.Channel
	}{
		"channels",
		id,
		channel,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "channel", data); err != nil {
		println(err.Error())
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) UpdateChannel(ctx context.Context, token, id string, channel sdk.Channel) ([]byte, error) {
	if err := gs.sdk.UpdateChannel(channel, token); err != nil {
		return []byte{}, err
	}
	return gs.ViewChannel(ctx, token, id)
}

func (gs *uiService) ListChannels(ctx context.Context, token string) ([]byte, error) {
	tpl, err := parseTemplate("channels", "channels.html")
	if err != nil {
		return []byte{}, err
	}

	filter := sdk.PageMetadata{
		Offset: uint64(0),
		Total:  uint64(100),
		Limit:  uint64(100),
	}
	chsPage, err := gs.sdk.Channels(token, filter)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		Channels     []sdk.Channel
	}{
		"channels",
		chsPage.Channels,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "channels", data); err != nil {
		println(err.Error())
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) RemoveChannel(ctx context.Context, token, id string) ([]byte, error) {
	err := gs.sdk.DeleteChannel(id, token)
	if err != nil {
		return []byte{}, err
	}
	return gs.ListChannels(ctx, token)
}

func (gs *uiService) Connect(ctx context.Context, token string, chIDs, thIDs []string) ([]byte, error) {
	cids := sdk.ConnectionIDs{
		ThingIDs:   thIDs,
		ChannelIDs: chIDs,
	}
	if err := gs.sdk.Connect(cids, token); err != nil {
		return []byte{}, err
	}

	return gs.ListThingByChannel(ctx, token, thIDs[0])
}

func (gs *uiService) ListThingByChannel(ctx context.Context, token, id string) ([]byte, error) {
	tpl, err := parseTemplate("thingconn", "thingconn.html")
	if err != nil {
		return []byte{}, err
	}

	thing, err := gs.sdk.Thing(id, token)
	if err != nil {
		return []byte{}, err
	}

	chsPage, err := gs.sdk.ChannelsByThing(token, id, 0, 100, false)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		ID           string
		Thing        sdk.Thing
		Channels     []sdk.Channel
	}{
		"things",
		id,
		thing,
		chsPage.Channels,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "thingconn", data); err != nil {
		println(err.Error())
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) ListGroupMembers(ctx context.Context, token, id string) ([]byte, error) {
	tpl, err := parseTemplate("groupconn", "groupconn.html")
	if err != nil {
		return []byte{}, err
	}

	group, err := gs.sdk.Group(id, token)
	if err != nil {
		return []byte{}, err
	}

	members, err := gs.sdk.Members(id, token, 0, 100)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		ID           string
		Group        sdk.Group
		Members      []string
	}{
		"groups",
		id,
		group,
		members.Members,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "groupconn", data); err != nil {
		println(err.Error())
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) ListChannelsByThing(ctx context.Context, token, id string) ([]byte, error) {
	tpl, err := parseTemplate("channelconn", "channelconn.html")
	if err != nil {
		return []byte{}, err
	}

	channel, err := gs.sdk.Channel(id, token)
	if err != nil {
		return []byte{}, err
	}

	thsPage, err := gs.sdk.ThingsByChannel(token, id, 0, 100, false)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		ID           string
		Channel      sdk.Channel
		Things       []sdk.Thing
	}{
		"channels",
		id,
		channel,
		thsPage.Things,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "channelconn", data); err != nil {
		println(err.Error())
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) DisconnectThing(ctx context.Context, token string, chIDs, thIDs []string) ([]byte, error) {
	for _, chID := range chIDs {
		for _, thID := range thIDs {
			if err := gs.sdk.DisconnectThing(thID, chID, token); err != nil {
				return []byte{}, err
			}
		}
	}

	return gs.ListThingByChannel(ctx, token, thIDs[0])
}

func (gs *uiService) DisconnectChannel(ctx context.Context, token string, chIDs, thIDs []string) ([]byte, error) {
	for _, thID := range thIDs {
		for _, chID := range chIDs {
			if err := gs.sdk.DisconnectThing(thID, chID, token); err != nil {
				return []byte{}, err
			}
		}
	}

	return gs.ListChannelsByThing(ctx, token, chIDs[0])
}

func (gs *uiService) CreateGroups(ctx context.Context, token string, groups ...sdk.Group) ([]byte, error) {
	for i := range groups {
		_, err := gs.sdk.CreateGroup(groups[i], token)
		if err != nil {
			return []byte{}, err
		}
	}
	return gs.ListGroups(ctx, token)
}

func (gs *uiService) ListGroups(ctx context.Context, token string) ([]byte, error) {
	tpl, err := parseTemplate("groups", "groups.html")
	if err != nil {
		return []byte{}, err
	}

	filter := sdk.PageMetadata{
		Offset: uint64(0),
		Total:  uint64(100),
		Limit:  uint64(100),
	}
	grpPage, err := gs.sdk.Groups(filter, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		Groups       []sdk.Group
	}{
		"groups",
		grpPage.Groups,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "groups", data); err != nil {
		println(err.Error())
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) ViewGroup(ctx context.Context, token, id string) ([]byte, error) {
	tpl, err := parseTemplate("group", "group.html")
	if err != nil {
		return []byte{}, err
	}

	group, err := gs.sdk.Group(id, token)
	if err != nil {
		return []byte{}, err
	}

	members, err := gs.sdk.Members(id, token, 0, 100)
	if err != nil {
		return []byte{}, err
	}
	data := struct {
		NavbarActive string
		ID           string
		Group        sdk.Group
		Members      []string
	}{
		"groups",
		id,
		group,
		members.Members,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "group", data); err != nil {
		println(err.Error())
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) Assign(ctx context.Context, token string, groupID, groupType string, memberIDs ...string) ([]byte, error) {
	if err := gs.sdk.Assign(memberIDs, groupType, groupID, token); err != nil {
		return []byte{}, err
	}
	return gs.ViewGroup(ctx, token, groupID)
}

func (gs *uiService) Unassign(ctx context.Context, token, groupID string, memberIDs ...string) ([]byte, error) {
	if err := gs.sdk.Unassign(token, groupID, memberIDs...); err != nil {
		return []byte{}, err
	}
	return gs.ViewGroup(ctx, token, groupID)
}

func (gs *uiService) UpdateGroup(ctx context.Context, token, id string, group sdk.Group) ([]byte, error) {
	if err := gs.sdk.UpdateGroup(group, token); err != nil {
		return []byte{}, err
	}
	return gs.ViewGroup(ctx, token, id)
}

func (gs *uiService) RemoveGroup(ctx context.Context, token, id string) ([]byte, error) {
	err := gs.sdk.DeleteGroup(id, token)
	if err != nil {
		return []byte{}, err
	}
	return []byte{}, nil
}

func (gs *uiService) Publish(ctx context.Context, thingKey string, msg messaging.Message) ([]byte, error) {
	err := gs.sdk.SendMessage(msg.Channel, string(msg.Payload), thingKey)
	if err != nil {
		return []byte{}, err
	}
	return gs.SendMessage(ctx, thingKey)
}

func (gs *uiService) SendMessage(ctx context.Context, token string) ([]byte, error) {
	tpl, err := parseTemplate("messages", "messages.html")
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
	}{
		"messages",
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "messages", data); err != nil {
		println(err.Error())
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) Login(ctx context.Context) ([]byte, error) {
	tpl, err := parseTemplate("login", "login.html")
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
	}{
		"dashboard",
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "login", data); err != nil {
		println(err.Error())
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) Logout(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (gs *uiService) Token(ctx context.Context, username, password string) (string, error) {
	token, err := gs.sdk.CreateToken(sdk.User{Email: username, Password: password})
	if err != nil {
		return token, err
	}
	return token, nil
}

func (gs *uiService) CreateUser(ctx context.Context, token string, users ...sdk.User) ([]byte, error) {
	for i := range users {
		_, err := gs.sdk.CreateUser(token, users[i])
		if err != nil {
			return []byte{}, err
		}
	}
	return gs.ListUsers(ctx, token)
}

func (gs *uiService) ViewUser(ctx context.Context, token, id string) ([]byte, error) {
	tpl, err := parseTemplate("user", "user.html")
	if err != nil {
		return []byte{}, err
	}
	user, err := gs.sdk.User(id, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		ID           string
		User         sdk.User
	}{
		"user",
		id,
		user,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "user", data); err != nil {
		println(err.Error())
	}
	return btpl.Bytes(), nil
}
func (gs *uiService) UpdateUser(ctx context.Context, token, id string, user sdk.User) ([]byte, error) {
	if err := gs.sdk.UpdateUser(user, token); err != nil {
		return []byte{}, err
	}
	return gs.ViewUser(ctx, token, id)
}
func (gs *uiService) UpdateUserPassword(ctx context.Context, token, id, oldPass, newPass string) ([]byte, error) {
	user, err := gs.sdk.User(token, id)
	if err != nil {
		return []byte{}, err
	}
	if err := gs.sdk.UpdatePassword(oldPass, newPass, token); err != nil {
		return []byte{}, err
	}
	user.Password = newPass
	token, err = gs.sdk.CreateToken(user)
	if err != nil {
		return []byte{}, err
	}
	return gs.ViewUser(ctx, token, id)
}
func (gs *uiService) ListUsers(ctx context.Context, token string) ([]byte, error) {
	tpl, err := parseTemplate("users", "users.html")
	if err != nil {
		return []byte{}, err
	}
	filter := sdk.PageMetadata{
		Offset: uint64(0),
		Total:  uint64(100),
		Limit:  uint64(100),
	}
	users, err := gs.sdk.Users(token, filter)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		Users        []sdk.User
	}{
		"users",
		users.Users,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "users", data); err != nil {
		println(err.Error())
	}

	return btpl.Bytes(), nil
}
