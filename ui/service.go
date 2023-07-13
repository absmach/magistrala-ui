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

	// ErrInvalidResetPass indicates an invalid reset password.
	ErrInvalidResetPass = errors.New("invalid reset password")
	// ErrConflict indicates that entity already exists.
	ErrConflict = errors.New("entity already exists")

	tmplFiles = []string{"header.html", "footer.html", "navbar.html"}
)

// Service specifies coap service API.
type Service interface {
	Index(ctx context.Context, token string) ([]byte, error)
	Login(ctx context.Context) ([]byte, error)
	Logout(ctx context.Context) ([]byte, error)
	PasswordResetRequest(ctx context.Context, email string) ([]byte, error)
	PasswordReset(ctx context.Context, token, password, confirmPass string) ([]byte, error)
	ShowPasswordReset(ctx context.Context) ([]byte, error)
	PasswordUpdate(ctx context.Context) ([]byte, error)
	UpdatePassword(ctx context.Context, token, oldPass, newPass string) ([]byte, error)
	UserProfile(ctx context.Context, token string) (sdk.User, error)
	Token(ctx context.Context, user sdk.User) (sdk.Token, error)
	RefreshToken(ctx context.Context, refreshToken string) (sdk.Token, error)
	CreateUsers(ctx context.Context, token string, user ...sdk.User) ([]byte, error)
	ListUsers(ctx context.Context, token, alertMessage string) ([]byte, error)
	ViewUser(ctx context.Context, token, userID string) ([]byte, error)
	UpdateUser(ctx context.Context, token, userID string, user sdk.User) ([]byte, error)
	UpdateUserTags(ctx context.Context, token, userID string, user sdk.User) ([]byte, error)
	UpdateUserIdentity(ctx context.Context, token, userID string, user sdk.User) ([]byte, error)
	UpdateUserOwner(ctx context.Context, token, userID string, user sdk.User) ([]byte, error)
	EnableUser(ctx context.Context, token, userID string) ([]byte, error)
	DisableUser(ctx context.Context, token, userID string) ([]byte, error)
	CreateThings(ctx context.Context, token string, things ...sdk.Thing) ([]byte, error)
	ListThings(ctx context.Context, token, alertMessage string) ([]byte, error)
	ViewThing(ctx context.Context, token, id string) ([]byte, error)
	UpdateThing(ctx context.Context, token, id string, thing sdk.Thing) ([]byte, error)
	UpdateThingTags(ctx context.Context, token, id string, thing sdk.Thing) ([]byte, error)
	UpdateThingSecret(ctx context.Context, token, id, secret string) ([]byte, error)
	UpdateThingOwner(ctx context.Context, token, id string, thing sdk.Thing) ([]byte, error)
	EnableThing(ctx context.Context, token, id string) ([]byte, error)
	DisableThing(ctx context.Context, token, id string) ([]byte, error)
	CreateChannels(ctx context.Context, token string, channels ...sdk.Channel) ([]byte, error)
	ListChannels(ctx context.Context, token, alertMessage string) ([]byte, error)
	ViewChannel(ctx context.Context, token, id string) ([]byte, error)
	UpdateChannel(ctx context.Context, token, id string, channel sdk.Channel) ([]byte, error)
	ListChannelsByThing(ctx context.Context, token, id string) ([]byte, error)
	ListThingsByChannel(ctx context.Context, token, id string) ([]byte, error)
	EnableChannel(ctx context.Context, token, id string) ([]byte, error)
	DisableChannel(ctx context.Context, token, id string) ([]byte, error)
	Connect(ctx context.Context, token string, connIDs sdk.ConnectionIDs) ([]byte, error)
	Disconnect(ctx context.Context, token string, connIDs sdk.ConnectionIDs) ([]byte, error)
	ConnectThing(ctx context.Context, token string, connIDs sdk.ConnectionIDs) ([]byte, error)
	ShareThing(ctx context.Context, token, chanID, userID string, actions []string) ([]byte, error)
	DisconnectThing(ctx context.Context, thID, chID, token string) ([]byte, error)
	ConnectChannel(ctx context.Context, token string, connIDs sdk.ConnectionIDs) ([]byte, error)
	DisconnectChannel(ctx context.Context, thID, chID, token string) ([]byte, error)
	AddThingsPolicy(ctx context.Context, token string, Policy sdk.Policy) ([]byte, error)
	DeleteThingsPolicy(ctx context.Context, token string, policy sdk.Policy) ([]byte, error)
	ListThingsPolicies(ctx context.Context, token string) ([]byte, error)
	UpdateThingsPolicy(ctx context.Context, token string, policy sdk.Policy) ([]byte, error)
	CreateGroups(ctx context.Context, token string, groups ...sdk.Group) ([]byte, error)
	ListGroupMembers(ctx context.Context, token, id string) ([]byte, error)
	Assign(ctx context.Context, token, groupID, memberID string, memberType []string) ([]byte, error)
	Unassign(ctx context.Context, token, groupID, memberID string) ([]byte, error)
	ViewGroup(ctx context.Context, token, id string) ([]byte, error)
	UpdateGroup(ctx context.Context, token, id string, group sdk.Group) ([]byte, error)
	ListGroups(ctx context.Context, token, alertMessage string) ([]byte, error)
	EnableGroup(ctx context.Context, token, id string) ([]byte, error)
	DisableGroup(ctx context.Context, token, id string) ([]byte, error)
	AddPolicy(ctx context.Context, token string, policy sdk.Policy) ([]byte, error)
	UpdatePolicy(ctx context.Context, token string, policy sdk.Policy) ([]byte, error)
	ListPolicies(ctx context.Context, token string) ([]byte, error)
	DeletePolicy(ctx context.Context, token string, policy sdk.Policy) ([]byte, error)
	Publish(ctx context.Context, token, thKey string, msg *messaging.Message) ([]byte, error)
	ReadMessage(ctx context.Context, token string) ([]byte, error)
	WsConnection(ctx context.Context, token, chID, thKey string) ([]byte, error)
	ListDeletedClients(ctx context.Context, token string) ([]byte, error)
}

var _ Service = (*uiService)(nil)

type uiService struct {
	sdk sdk.SDK
}

// New instantiates the HTTP adapter implementation.
func New(sdk sdk.SDK) Service {
	return &uiService{
		sdk: sdk,
	}
}

func parseTemplate(name string, tmpls ...string) (tpl *template.Template, err error) {
	tpl = template.New(name)
	tpl = tpl.Funcs(template.FuncMap{
		"toJSON": func(data map[string]interface{}) string {
			ret, _ := json.Marshal(data)
			return string(ret)
		},
		"toSlice": func(data []string) string {
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

	user, err := gs.UserProfile(ctx, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		User         sdk.User
	}{
		"dashboard",
		user,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "index", data); err != nil {
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

func (gs *uiService) PasswordResetRequest(ctx context.Context, email string) ([]byte, error) {
	if err := gs.sdk.ResetPasswordRequest(email); err != nil {
		return []byte{}, err
	}
	return gs.Login(ctx)
}

func (gs *uiService) PasswordReset(ctx context.Context, token, password, confirmPass string) ([]byte, error) {
	if err := gs.sdk.ResetPassword(token, password, confirmPass); err != nil {
		return []byte{}, err
	}
	return gs.Login(ctx)
}

func (gs *uiService) ShowPasswordReset(ctx context.Context) ([]byte, error) {
	tpl, err := parseTemplate("resetPassword", "resetPassword.html")
	if err != nil {
		return []byte{}, err
	}
	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "resetPassword", ""); err != nil {
		println(err.Error())
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) PasswordUpdate(ctx context.Context) ([]byte, error) {
	tpl, err := parseTemplate("updatePassword", "updatePassword.html")
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
	}{
		"password",
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "updatePassword", data); err != nil {
		println(err.Error())
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) Token(ctx context.Context, user sdk.User) (sdk.Token, error) {
	token, err := gs.sdk.CreateToken(user)
	if err != nil {
		return sdk.Token{}, err
	}
	return token, nil
}

func (gs *uiService) RefreshToken(cxt context.Context, refreshToken string) (sdk.Token, error) {
	token, err := gs.sdk.RefreshToken(refreshToken)
	if err != nil {
		return sdk.Token{}, err
	}
	return token, nil
}

func (gs *uiService) Logout(ctx context.Context) ([]byte, error) {
	return nil, nil
}

func (gs *uiService) UserProfile(ctx context.Context, token string) (sdk.User, error) {
	user, err := gs.sdk.UserProfile(token)
	if err != nil {
		return sdk.User{}, err
	}

	return user, nil
}

func (gs *uiService) UpdatePassword(ctx context.Context, token, oldPass, newPass string) ([]byte, error) {
	if _, err := gs.sdk.UpdatePassword(oldPass, newPass, token); err != nil {
		return []byte{}, err
	}
	return nil, nil
}

func (gs *uiService) CreateUsers(ctx context.Context, token string, users ...sdk.User) ([]byte, error) {
	var alertMessage string
	for i := range users {
		_, err := gs.sdk.CreateUser(users[i], token)
		if err != nil {
			if errors.Contains(err, ErrConflict) {
				alertMessage = "User already Exists"
				continue
			}
			return []byte{}, err
		}
	}
	return gs.ListUsers(ctx, token, alertMessage)
}

func (gs *uiService) ListUsers(ctx context.Context, token, alertMessage string) ([]byte, error) {
	tpl, err := parseTemplate("users", "users.html")
	if err != nil {
		return []byte{}, err
	}
	pgm := sdk.PageMetadata{
		Offset: uint64(0),
		Total:  uint64(100),
		Limit:  uint64(100),
	}
	users, err := gs.sdk.Users(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		Users        []sdk.User
		AlertMessage string
	}{
		"users",
		users.Users,
		alertMessage,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "users", data); err != nil {
		println(err.Error())
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) ViewUser(ctx context.Context, token, userID string) ([]byte, error) {
	tpl, err := parseTemplate("user", "user.html")
	if err != nil {
		return []byte{}, err
	}
	user, err := gs.sdk.User(userID, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		ID           string
		User         sdk.User
	}{
		"user",
		userID,
		user,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "user", data); err != nil {
		println(err.Error())
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) UpdateUser(ctx context.Context, token, userID string, user sdk.User) ([]byte, error) {
	if _, err := gs.sdk.UpdateUser(user, token); err != nil {
		return []byte{}, err
	}

	return gs.ViewUser(ctx, token, userID)
}

func (gs *uiService) UpdateUserTags(ctx context.Context, token, userID string, user sdk.User) ([]byte, error) {
	if _, err := gs.sdk.UpdateUserTags(user, token); err != nil {
		return []byte{}, err
	}

	return gs.ViewUser(ctx, token, userID)
}

func (gs *uiService) UpdateUserIdentity(ctx context.Context, token, userID string, user sdk.User) ([]byte, error) {
	if _, err := gs.sdk.UpdateUserIdentity(user, token); err != nil {
		return []byte{}, err
	}

	return gs.ViewUser(ctx, token, userID)
}

func (gs *uiService) UpdateUserOwner(ctx context.Context, token, userID string, user sdk.User) ([]byte, error) {
	if _, err := gs.sdk.UpdateUserIdentity(user, token); err != nil {
		return []byte{}, err
	}

	return gs.ViewUser(ctx, token, userID)
}

func (gs *uiService) EnableUser(ctx context.Context, token, userID string) ([]byte, error) {
	if _, err := gs.sdk.EnableUser(userID, token); err != nil {
		return []byte{}, err
	}
	return gs.ListUsers(ctx, token, "")
}

func (gs *uiService) DisableUser(ctx context.Context, token, userID string) ([]byte, error) {
	if _, err := gs.sdk.DisableUser(userID, token); err != nil {
		return []byte{}, err
	}

	return gs.ListUsers(ctx, token, "")
}

func (gs *uiService) CreateThings(ctx context.Context, token string, things ...sdk.Thing) ([]byte, error) {
	var alertMessage string
	for _, thing := range things {
		_, err := gs.sdk.CreateThing(thing, token)
		if err != nil {
			if errors.Contains(err, ErrConflict) {
				alertMessage = "Thing already Exists!"
				continue
			}
			return []byte{}, err
		}
	}
	return gs.ListThings(ctx, token, alertMessage)
}

func (gs *uiService) ListThings(ctx context.Context, token, alertMessage string) ([]byte, error) {
	tpl, err := parseTemplate("things", "things.html")
	if err != nil {
		return []byte{}, err
	}
	pgm := sdk.PageMetadata{
		Offset:     uint64(0),
		Total:      uint64(100),
		Limit:      uint64(100),
		Visibility: "all",
	}
	things, err := gs.sdk.Things(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		Things       []sdk.Thing
		AlertMessage string
	}{
		"things",
		things.Things,
		alertMessage,
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
		"thing",
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
	if _, err := gs.sdk.UpdateThing(thing, token); err != nil {
		return []byte{}, err
	}

	return gs.ViewThing(ctx, token, id)
}

func (gs *uiService) UpdateThingTags(ctx context.Context, token, id string, thing sdk.Thing) ([]byte, error) {
	if _, err := gs.sdk.UpdateThingTags(thing, token); err != nil {
		return []byte{}, err
	}

	return gs.ViewThing(ctx, token, id)
}

func (gs *uiService) UpdateThingSecret(ctx context.Context, token, id, secret string) ([]byte, error) {
	if _, err := gs.sdk.UpdateThingSecret(id, secret, token); err != nil {
		return []byte{}, err
	}

	return gs.ViewThing(ctx, token, id)
}

func (gs *uiService) UpdateThingOwner(ctx context.Context, token, id string, thing sdk.Thing) ([]byte, error) {
	if _, err := gs.sdk.UpdateThingOwner(thing, token); err != nil {
		return []byte{}, nil
	}

	return gs.ListThings(ctx, token, "")
}

func (gs *uiService) EnableThing(ctx context.Context, token, id string) ([]byte, error) {
	if _, err := gs.sdk.EnableThing(id, token); err != nil {
		return []byte{}, err
	}

	return gs.ListThings(ctx, token, "")
}

func (gs *uiService) DisableThing(ctx context.Context, token, id string) ([]byte, error) {
	if _, err := gs.sdk.DisableThing(id, token); err != nil {
		return []byte{}, err
	}

	return gs.ListThings(ctx, token, "")
}

func (gs *uiService) CreateChannels(ctx context.Context, token string, channels ...sdk.Channel) ([]byte, error) {
	var alertMessage string
	for _, channel := range channels {
		_, err := gs.sdk.CreateChannel(channel, token)
		if err != nil {
			if errors.Contains(err, ErrConflict) {
				alertMessage = "Channel already Exists"
				continue
			}
			return []byte{}, err
		}
	}
	return gs.ListChannels(ctx, token, alertMessage)
}

func (gs *uiService) ListChannels(ctx context.Context, token, alertMessage string) ([]byte, error) {
	tpl, err := parseTemplate("channels", "channels.html")
	if err != nil {
		return []byte{}, err
	}

	filter := sdk.PageMetadata{
		Offset:     uint64(0),
		Total:      uint64(100),
		Limit:      uint64(100),
		Visibility: "all",
	}
	chsPage, err := gs.sdk.Channels(filter, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		Channels     []sdk.Channel
		AlertMessage string
	}{
		"channels",
		chsPage.Channels,
		alertMessage,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "channels", data); err != nil {
		println(err.Error())
	}

	return btpl.Bytes(), nil
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
	if _, err := gs.sdk.UpdateChannel(channel, token); err != nil {
		return []byte{}, err
	}
	return gs.ViewChannel(ctx, token, id)
}

func (gs *uiService) EnableChannel(ctx context.Context, token, id string) ([]byte, error) {
	if _, err := gs.sdk.EnableChannel(id, token); err != nil {
		return []byte{}, err
	}

	return gs.ListChannels(ctx, token, "")
}

func (gs *uiService) DisableChannel(ctx context.Context, token, id string) ([]byte, error) {
	if _, err := gs.sdk.DisableChannel(id, token); err != nil {
		return []byte{}, err
	}

	return gs.ListChannels(ctx, token, "")
}

func (gs *uiService) ConnectThing(ctx context.Context, token string, connIDs sdk.ConnectionIDs) ([]byte, error) {
	if err := gs.sdk.Connect(connIDs, token); err != nil {
		return []byte{}, err
	}

	return gs.ListThingsByChannel(ctx, token, connIDs.ChannelIDs[0])
}

func (gs *uiService) ShareThing(ctx context.Context, token, chanID, userID string, actions []string) ([]byte, error) {
	if err := gs.sdk.ShareThing(chanID, userID, actions, token); err != nil {
		return []byte{}, err
	}

	return gs.ListThingsByChannel(ctx, token, chanID)
}

func (gs *uiService) DisconnectThing(ctx context.Context, thID, chID, token string) ([]byte, error) {
	if err := gs.sdk.DisconnectThing(thID, chID, token); err != nil {
		return []byte{}, err
	}

	return gs.ListThingsByChannel(ctx, token, chID)
}

func (gs *uiService) ConnectChannel(ctx context.Context, token string, connIDs sdk.ConnectionIDs) ([]byte, error) {
	if err := gs.sdk.Connect(connIDs, token); err != nil {
		return []byte{}, err
	}

	return gs.ListChannelsByThing(ctx, token, connIDs.ThingIDs[0])
}

func (gs *uiService) DisconnectChannel(ctx context.Context, thID, chID, token string) ([]byte, error) {
	if err := gs.sdk.DisconnectThing(thID, chID, token); err != nil {
		return []byte{}, err
	}

	return gs.ListChannelsByThing(ctx, token, thID)
}

func (gs *uiService) ListChannelsByThing(ctx context.Context, token, id string) ([]byte, error) {
	tpl, err := parseTemplate("thingconn", "thingconn.html")
	if err != nil {
		return []byte{}, err
	}

	thing, err := gs.sdk.Thing(id, token)
	if err != nil {
		return []byte{}, err
	}
	pgm := sdk.PageMetadata{
		Offset: uint64(0),
		Total:  uint64(100),
		Limit:  uint64(100),
	}

	chsPage, err := gs.sdk.ChannelsByThing(id, pgm, token)
	if err != nil {
		return []byte{}, err
	}

	allchsPage, err := gs.sdk.Channels(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	plcPage, err := gs.sdk.ListThingPolicies(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		ID           string
		Thing        sdk.Thing
		Channels     []sdk.Channel
		AllChannels  []sdk.Channel
		Policies     []sdk.Policy
	}{
		"things",
		id,
		thing,
		chsPage.Channels,
		allchsPage.Channels,
		plcPage.Policies,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "thingconn", data); err != nil {
		println(err.Error())
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) Connect(ctx context.Context, token string, connIDs sdk.ConnectionIDs) ([]byte, error) {
	if err := gs.sdk.Connect(connIDs, token); err != nil {
		return []byte{}, err
	}

	return gs.ListThingsByChannel(ctx, token, connIDs.ChannelIDs[0])
}

func (gs *uiService) Disconnect(ctx context.Context, token string, connIDs sdk.ConnectionIDs) ([]byte, error) {
	if err := gs.sdk.Disconnect(connIDs, token); err != nil {
		return []byte{}, err
	}

	return gs.ListThingsByChannel(ctx, token, connIDs.ChannelIDs[0])
}

func (gs *uiService) ListThingsByChannel(ctx context.Context, token, id string) ([]byte, error) {
	tpl, err := parseTemplate("channelconn", "channelconn.html")
	if err != nil {
		return []byte{}, err
	}

	channel, err := gs.sdk.Channel(id, token)
	if err != nil {
		return []byte{}, err
	}

	pgm := sdk.PageMetadata{
		Offset: uint64(0),
		Total:  uint64(100),
		Limit:  uint64(100),
	}

	thsPage, err := gs.sdk.ThingsByChannel(id, pgm, token)
	if err != nil {
		return []byte{}, err
	}

	allthsPage, err := gs.sdk.Things(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	plcPage, err := gs.sdk.ListThingPolicies(pgm, token)
	if err != nil {
		return []byte{}, err
	}
	users, err := gs.sdk.Users(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		ID           string
		Channel      sdk.Channel
		Things       []sdk.Thing
		AllThings    []sdk.Thing
		Policies     []sdk.Policy
		Users        []sdk.User
	}{
		"channels",
		id,
		channel,
		thsPage.Things,
		allthsPage.Things,
		plcPage.Policies,
		users.Users,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "channelconn", data); err != nil {
		println(err.Error())
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) ListThingsPolicies(ctx context.Context, token string) ([]byte, error) {
	tpl, err := parseTemplate("thingsPolicies", "thingsPolicies.html")
	if err != nil {
		return []byte{}, err
	}

	pgm := sdk.PageMetadata{
		Offset: uint64(0),
		Total:  uint64(100),
		Limit:  uint64(100),
	}
	plcPage, err := gs.sdk.ListThingPolicies(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	chsPage, err := gs.sdk.Channels(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	thsPage, err := gs.sdk.Things(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		Policies     []sdk.Policy
		Channels     []sdk.Channel
		Things       []sdk.Thing
	}{
		"thingsPolicies",
		plcPage.Policies,
		chsPage.Channels,
		thsPage.Things,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "thingsPolicies", data); err != nil {
		println(err.Error())
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) AddThingsPolicy(ctx context.Context, token string, policy sdk.Policy) ([]byte, error) {
	if err := gs.sdk.CreateThingPolicy(policy, token); err != nil {
		return []byte{}, err
	}

	return gs.ListThingsPolicies(ctx, token)
}

func (gs *uiService) DeleteThingsPolicy(ctx context.Context, token string, policy sdk.Policy) ([]byte, error) {
	if err := gs.sdk.DeleteThingPolicy(policy, token); err != nil {
		return []byte{}, err
	}

	return gs.ListThingsPolicies(ctx, token)
}

func (gs *uiService) UpdateThingsPolicy(ctx context.Context, token string, policy sdk.Policy) ([]byte, error) {
	if err := gs.sdk.UpdateThingPolicy(policy, token); err != nil {
		return []byte{}, err
	}

	return gs.ListThingsPolicies(ctx, token)
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

	pgm := sdk.PageMetadata{
		Offset: uint64(0),
		Total:  uint64(100),
		Limit:  uint64(100),
	}

	members, err := gs.sdk.Members(id, pgm, token)
	if err != nil {
		return []byte{}, err
	}

	users, err := gs.sdk.Users(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	plcPage, err := gs.sdk.ListUserPolicies(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		ID           string
		Group        sdk.Group
		Members      []sdk.User
		Users        []sdk.User
		Policies     []sdk.Policy
	}{
		"groups",
		id,
		group,
		members.Members,
		users.Users,
		plcPage.Policies,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "groupconn", data); err != nil {
		println(err.Error())
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) CreateGroups(ctx context.Context, token string, groups ...sdk.Group) ([]byte, error) {
	var alertMessage string
	for _, group := range groups {
		_, err := gs.sdk.CreateGroup(group, token)
		if err != nil {
			if errors.Contains(err, ErrConflict) {
				alertMessage = "Group already Exists"
				continue
			}
			return []byte{}, err
		}
	}
	return gs.ListGroups(ctx, token, alertMessage)
}

func (gs *uiService) ListGroups(ctx context.Context, token, alertMessage string) ([]byte, error) {
	tpl, err := parseTemplate("groups", "groups.html")
	if err != nil {
		return []byte{}, err
	}

	pgm := sdk.PageMetadata{
		Offset: uint64(0),
		Total:  uint64(100),
		Limit:  uint64(100),
	}
	grpPage, err := gs.sdk.Groups(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		Groups       []sdk.Group
		AlertMessage string
	}{
		"groups",
		grpPage.Groups,
		alertMessage,
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

	pgm := sdk.PageMetadata{
		Offset: 0,
		Limit:  100,
	}

	members, err := gs.sdk.Members(id, pgm, token)
	if err != nil {
		return []byte{}, err
	}
	data := struct {
		NavbarActive string
		ID           string
		Group        sdk.Group
		Members      []sdk.User
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

func (gs *uiService) Assign(ctx context.Context, token, groupID, memberID string, memberType []string) ([]byte, error) {
	if err := gs.sdk.Assign(memberType, memberID, groupID, token); err != nil {
		return []byte{}, err
	}

	return gs.ListGroupMembers(ctx, token, groupID)
}

func (gs *uiService) Unassign(ctx context.Context, token, groupID, memberID string) ([]byte, error) {
	if err := gs.sdk.Unassign(memberID, groupID, token); err != nil {
		return []byte{}, err
	}

	return gs.ListGroupMembers(ctx, token, groupID)
}

func (gs *uiService) UpdateGroup(ctx context.Context, token, id string, group sdk.Group) ([]byte, error) {
	if _, err := gs.sdk.UpdateGroup(group, token); err != nil {
		return []byte{}, err
	}
	return gs.ViewGroup(ctx, token, id)
}

func (gs *uiService) EnableGroup(ctx context.Context, token, id string) ([]byte, error) {
	if _, err := gs.sdk.EnableGroup(id, token); err != nil {
		return []byte{}, err
	}

	return gs.ListGroups(ctx, token, "")
}

func (gs *uiService) DisableGroup(ctx context.Context, token, id string) ([]byte, error) {
	if _, err := gs.sdk.DisableGroup(id, token); err != nil {
		return []byte{}, err
	}

	return gs.ListGroups(ctx, token, "")
}

func (gs *uiService) AddPolicy(ctx context.Context, token string, policy sdk.Policy) ([]byte, error) {
	if err := gs.sdk.CreateUserPolicy(policy, token); err != nil {
		return []byte{}, err
	}

	return gs.ListPolicies(ctx, token)
}

func (gs *uiService) ListPolicies(ctx context.Context, token string) ([]byte, error) {
	tpl, err := parseTemplate("policies", "policies.html")
	if err != nil {
		return []byte{}, err
	}

	pgm := sdk.PageMetadata{
		Offset: uint64(0),
		Total:  uint64(100),
		Limit:  uint64(100),
	}
	plcPage, err := gs.sdk.ListUserPolicies(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	grpPage, err := gs.sdk.Groups(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	users, err := gs.sdk.Users(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		Policies     []sdk.Policy
		Groups       []sdk.Group
		Users        []sdk.User
	}{
		"policies",
		plcPage.Policies,
		grpPage.Groups,
		users.Users,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "policies", data); err != nil {
		println(err.Error())
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) UpdatePolicy(ctx context.Context, token string, policy sdk.Policy) ([]byte, error) {
	if err := gs.sdk.UpdateUserPolicy(policy, token); err != nil {
		return []byte{}, err
	}

	return gs.ListPolicies(ctx, token)
}

func (gs *uiService) DeletePolicy(ctx context.Context, token string, policy sdk.Policy) ([]byte, error) {
	if err := gs.sdk.DeleteUserPolicy(policy, token); err != nil {
		return []byte{}, err
	}

	return gs.ListPolicies(ctx, token)
}

func (gs *uiService) Publish(ctx context.Context, token, thKey string, msg *messaging.Message) ([]byte, error) {
	err := gs.sdk.SendMessage(msg.Channel, string(msg.Payload), thKey)
	if err != nil {
		return []byte{}, err
	}

	return gs.ListThingsByChannel(ctx, token, msg.Channel)
}

func (gs *uiService) ReadMessage(ctx context.Context, token string) ([]byte, error) {
	tpl, err := parseTemplate("messagesread", "messagesread.html")
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
	}{
		"readmessages",
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "messagesread", data); err != nil {
		println(err.Error())
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) WsConnection(ctx context.Context, token, chID, thKey string) ([]byte, error) {
	tpl, err := parseTemplate("messagesread", "messagesread.html")
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		ChanID       string
		ThingKey     string
	}{
		"readmessages",
		chID,
		thKey,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "messagesread", data); err != nil {
		println(err.Error())
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) ListDeletedClients(ctx context.Context, token string) ([]byte, error) {
	tpl, err := parseTemplate("deletedClients", "deletedClients.html")
	if err != nil {
		return []byte{}, err
	}
	pgm := sdk.PageMetadata{
		Offset: uint64(0),
		Total:  uint64(100),
		Limit:  uint64(100),
		Status: "disabled",
	}
	users, err := gs.sdk.Users(pgm, token)
	if err != nil {
		return []byte{}, err
	}
	groups, err := gs.sdk.Groups(pgm, token)
	if err != nil {
		return []byte{}, err
	}
	things, err := gs.sdk.Things(pgm, token)
	if err != nil {
		return []byte{}, err
	}
	channels, err := gs.sdk.Channels(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		Users        []sdk.User
		Groups       []sdk.Group
		Things       []sdk.Thing
		Channels     []sdk.Channel
	}{
		"deleted",
		users.Users,
		groups.Groups,
		things.Things,
		channels.Channels,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "deletedClients", data); err != nil {
		println(err.Error())
	}

	return btpl.Bytes(), nil
}
