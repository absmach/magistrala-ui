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
	"log"
	"sync"
	"time"

	"golang.org/x/exp/slices"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/mainflux/agent/pkg/bootstrap"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/mainflux/mainflux/pkg/messaging"
	"github.com/mainflux/senml"

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

	tmplFiles    = []string{"header.html", "footer.html", "navbar.html"}
	userActions  = []string{"g_list", "g_update", "g_delete", "g_add", "c_list", "c_update", "c_delete"}
	thingActions = []string{"m_read", "m_write"}
)

// Service specifies service API.
type Service interface {
	// Index displays the landing page of the UI.
	Index(ctx context.Context, token string) ([]byte, error)
	// Login displays the login page.
	Login(ctx context.Context, alertMessage string) ([]byte, error)
	// Logout deletes the access token and refresh token from the cookies and logs the user out of the UI.
	Logout(ctx context.Context) ([]byte, error)
	// PasswordResetRequest sends an email with a link to the password reset page with a valid request token.
	PasswordResetRequest(ctx context.Context, email string) ([]byte, error)
	// PasswordReset resets the user's password.
	PasswordReset(ctx context.Context, token, password, confirmPass string) ([]byte, error)
	// ShowPasswordReset displays the password reset page.
	ShowPasswordReset(ctx context.Context) ([]byte, error)
	// PasswordUpdate displays the password update page.
	PasswordUpdate(ctx context.Context, alertMessage string) ([]byte, error)
	// UpdatePassword updates the user's old password to the new password.
	UpdatePassword(ctx context.Context, token, oldPass, newPass string) ([]byte, error)
	// UserProfile retrieves information about the logged in user.
	UserProfile(ctx context.Context, token string) (sdk.User, error)
	// Token provides a user with an access token and a refresh token.
	Token(ctx context.Context, user sdk.User) (sdk.Token, error)
	// RefreshToken retrieves a new access token and refresh token from the provided refresh token.
	RefreshToken(ctx context.Context, refreshToken string) (sdk.Token, error)
	// CreateUsers creates new users.
	CreateUsers(ctx context.Context, token string, user ...sdk.User) ([]byte, error)
	// ListUsers retrieves users owned/shared by a user.
	ListUsers(ctx context.Context, token, alertMessage string) ([]byte, error)
	// ViewUser retrieves information about the user with the given ID.
	ViewUser(ctx context.Context, token, userID string) ([]byte, error)
	// UpdateUser updates the user with the given ID.
	UpdateUser(ctx context.Context, token, userID string, user sdk.User) ([]byte, error)
	// UpdateUserTags updates the tags of the user with the given ID.
	UpdateUserTags(ctx context.Context, token, userID string, user sdk.User) ([]byte, error)
	// UpdateUserIdentity updates the identity of the user with the given ID.
	UpdateUserIdentity(ctx context.Context, token, userID string, user sdk.User) ([]byte, error)
	// UpdateUserOwner updates the owner of the user with the given ID.
	UpdateUserOwner(ctx context.Context, token, userID string, user sdk.User) ([]byte, error)
	// EnableUser updates the status of a user with the given ID to enabled.
	EnableUser(ctx context.Context, token, userID string) ([]byte, error)
	// DisableUser updates the status of a user with the given ID to disabled.
	DisableUser(ctx context.Context, token, userID string) ([]byte, error)
	// CreateThings creates new things.
	CreateThings(ctx context.Context, token string, things ...sdk.Thing) ([]byte, error)
	// ListThings retrieves things owned/shared by a user.
	ListThings(ctx context.Context, token, alertMessage string) ([]byte, error)
	// ViewThing retrieves information about the thing with the given ID.
	ViewThing(ctx context.Context, token, id string) ([]byte, error)
	// UpdateThing updates the thing with the given ID.
	UpdateThing(ctx context.Context, token, id string, thing sdk.Thing) ([]byte, error)
	// UpdateThingTags updates the tags of the thing with the given ID.
	UpdateThingTags(ctx context.Context, token, id string, thing sdk.Thing) ([]byte, error)
	// UpdateThingSecret updates the secret of the thing with the given ID.
	UpdateThingSecret(ctx context.Context, token, id, secret string) ([]byte, error)
	// UpdateThingOwner updates the owner of the thing with the given ID
	UpdateThingOwner(ctx context.Context, token, id string, thing sdk.Thing) ([]byte, error)
	// EnableThing updates the status of the thing with the given ID to enabled.
	EnableThing(ctx context.Context, token, id string) ([]byte, error)
	// DisableThing updates the status of the thing with the given ID to disabled
	DisableThing(ctx context.Context, token, id string) ([]byte, error)
	// CreateChannels creates new channels.
	CreateChannels(ctx context.Context, token string, channels ...sdk.Channel) ([]byte, error)
	// ListChannels retrieves channels owned/shared by a user.
	ListChannels(ctx context.Context, token, alertMessage string) ([]byte, error)
	// ViewChannel retrievs information about the channel with the given ID.
	ViewChannel(ctx context.Context, token, id string) ([]byte, error)
	// UpdateChannel updates the channel with the given ID.
	UpdateChannel(ctx context.Context, token, id string, channel sdk.Channel) ([]byte, error)
	// ListChannelsByThing retrieves a list of channels based on the given thing ID.
	ListChannelsByThing(ctx context.Context, token, id string) ([]byte, error)
	// ListThingsByChannel retrieves a list of things based on the given channel ID.
	ListThingsByChannel(ctx context.Context, token, id string) ([]byte, error)
	// EnableChannel updates the status of the channel with the given ID to enabled.
	EnableChannel(ctx context.Context, token, id string) ([]byte, error)
	// DisableChannel updates the status of the channel with the given ID to disabled.
	DisableChannel(ctx context.Context, token, id string) ([]byte, error)
	// Connect bulk connects things to channel(s) specified by ID.
	Connect(ctx context.Context, token string, connIDs sdk.ConnectionIDs) ([]byte, error)
	// Disconnect bulk disconnects thinfs to channel(s) specified by ID.
	Disconnect(ctx context.Context, token string, connIDs sdk.ConnectionIDs) ([]byte, error)
	// ConnectThing connects a thing to a channel specified by ID.
	ConnectThing(ctx context.Context, token string, connIDs sdk.ConnectionIDs) ([]byte, error)
	// ShareThing shares things connected to a channel with a user
	ShareThing(ctx context.Context, token, chanID, userID string, actions []string) ([]byte, error)
	// DisconnectThing disconnects a thing from a channel specified by ID.
	DisconnectThing(ctx context.Context, thID, chID, token string) ([]byte, error)
	// Connect Channel connects a channel to a thing specified by ID.
	ConnectChannel(ctx context.Context, token string, connIDs sdk.ConnectionIDs) ([]byte, error)
	// DisconnectChannel disconnects a channel from a thing specified by ID.
	DisconnectChannel(ctx context.Context, thID, chID, token string) ([]byte, error)
	// AddThingsPolicy adds a thing's policy on a channel.
	AddThingsPolicy(ctx context.Context, token string, Policy sdk.Policy) ([]byte, error)
	// DeleteThingsPolicy removes a thing's policy on a channel
	DeleteThingsPolicy(ctx context.Context, token string, policy sdk.Policy) ([]byte, error)
	// ListThingsPolicies retrieves the policies of things.
	ListThingsPolicies(ctx context.Context, token string) ([]byte, error)
	// UpdateThingsPolicy updates the policy that a thing has over a channel.
	UpdateThingsPolicy(ctx context.Context, token string, policy sdk.Policy) ([]byte, error)
	// CreateGroups creates new groups.
	CreateGroups(ctx context.Context, token string, groups ...sdk.Group) ([]byte, error)
	// ListGroupMembers retrieves the members of a group with a given ID.
	ListGroupMembers(ctx context.Context, token, id string) ([]byte, error)
	// Assign adds a user to a group.
	Assign(ctx context.Context, token, groupID, memberID string, memberType []string) ([]byte, error)
	// Unassign removes a user from a group.
	Unassign(ctx context.Context, token, groupID, memberID string) ([]byte, error)
	// ViewGroup retrieves information about a group with a given ID.
	ViewGroup(ctx context.Context, token, id string) ([]byte, error)
	// UpdateGroup updates the group with the given ID.
	UpdateGroup(ctx context.Context, token, id string, group sdk.Group) ([]byte, error)
	// ListGroups retrieves the groups owned/shared by a user.
	ListGroups(ctx context.Context, token, alertMessage string) ([]byte, error)
	// EnableGroup updates the status of the group to enabled.
	EnableGroup(ctx context.Context, token, id string) ([]byte, error)
	// DisableGroup updates the status of the group to disabled.
	DisableGroup(ctx context.Context, token, id string) ([]byte, error)
	// AddPolicy adds a user's policy on a group effectively adding the user to the group.
	AddPolicy(ctx context.Context, token string, policy sdk.Policy) ([]byte, error)
	// UpdatePolicy updates the policy a user has over a group.
	UpdatePolicy(ctx context.Context, token string, policy sdk.Policy) ([]byte, error)
	// ListPolicies retrieves the policies of the users.
	ListPolicies(ctx context.Context, token string) ([]byte, error)
	// DeletePolicy removes a user's policies on a group effectively removing the user from the group.
	DeletePolicy(ctx context.Context, token string, policy sdk.Policy) ([]byte, error)
	// Publish facilitates a thing publishin messages to a channel.
	Publish(ctx context.Context, token, thKey string, msg *messaging.Message) ([]byte, error)
	// ReadMessage facilitates a thing reading messages published in a channel.
	ReadMessage(ctx context.Context, token string) ([]byte, error)
	// WsConnection creates a web socket connection that allows continuous reading of messages published in a channel.
	WsConnection(ctx context.Context, token, chID, thKey string) ([]byte, error)
	// ListDeletedClients retrieves a list of clients that have been deleted.
	ListDeletedClients(ctx context.Context, token string) ([]byte, error)
	// CreateBootstrap creates a new bootstrap config.
	CreateBootstrap(ctx context.Context, token string, config ...sdk.BootstrapConfig) ([]byte, error)
	// ListBootstrap retrieves all bootstrap configs.
	ListBootstrap(ctx context.Context, token string) ([]byte, error)
	// UpdateBootstrap allows update of bootstrap name and content.
	UpdateBootstrap(ctx context.Context, token string, config sdk.BootstrapConfig) ([]byte, error)
	// UpdateBootstrapConnections updates connected channels on bootstrap configs.
	UpdateBootstrapConnections(ctx context.Context, token string, config sdk.BootstrapConfig) ([]byte, error)
	// UpdateBootstrapCerts updates bootstrap certs.
	UpdateBootstrapCerts(ctx context.Context, token string, config sdk.BootstrapConfig) ([]byte, error)
	// DeleteBootstrap deletes bootstrap config given an id.
	DeleteBootstrap(ctx context.Context, token, id string) ([]byte, error)
	// ViewBootstrap retrieves a bootstrap config by thing id.
	ViewBootstrap(ctx context.Context, token, id string) ([]byte, error)
	// GetRemoteTerminal returns remote terminal for a bootstrap config with mainflux agent installed.
	GetRemoteTerminal(ctx context.Context, id string) ([]byte, error)
	// ProcessTerminalCommand sends mqtt command to agent and retrieves a response asynchronously.
	ProcessTerminalCommand(ctx context.Context, id, token, command string, res chan string) error
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

func (gs *uiService) parseTemplate(name string, tmpls ...string) (tpl *template.Template, err error) {
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
		"contains": func(data []string, substring string) bool {

			return slices.Contains(data, substring)
		},
		"authorizeUser": func(subject, object, action, entityType string) bool {
			aReq := sdk.AccessRequest{
				Subject:    subject,
				Object:     object,
				Action:     action,
				EntityType: entityType,
			}

			authorized, _ := gs.sdk.AuthorizeUser(aReq, "")

			return authorized
		},
		"authorizeThing": func(subject, object, action, entityType string) bool {
			var aReq = sdk.AccessRequest{
				Subject:    subject,
				Object:     object,
				Action:     action,
				EntityType: entityType,
			}

			authorizeThing, _, _ := gs.sdk.AuthorizeThing(aReq, "")

			return authorizeThing
		},
		"disableService": func(service string) bool {
			if _, err := gs.sdk.Health(service); err != nil {
				return true
			}
			return false
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
	tpl, err := gs.parseTemplate("index", "index.html")
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

func (gs *uiService) Login(ctx context.Context, alertMessage string) ([]byte, error) {
	tpl, err := gs.parseTemplate("login", "login.html")
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		AlertMessage string
	}{
		"dashboard",
		alertMessage,
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
	return gs.Login(ctx, fmt.Sprintf("Reset password link sent to %s", email))
}

func (gs *uiService) PasswordReset(ctx context.Context, token, password, confirmPass string) ([]byte, error) {
	if err := gs.sdk.ResetPassword(token, password, confirmPass); err != nil {
		return []byte{}, err
	}
	return gs.Login(ctx, "")
}

func (gs *uiService) ShowPasswordReset(ctx context.Context) ([]byte, error) {
	tpl, err := gs.parseTemplate("resetPassword", "resetPassword.html")
	if err != nil {
		return []byte{}, err
	}
	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "resetPassword", ""); err != nil {
		println(err.Error())
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) PasswordUpdate(ctx context.Context, alertMessage string) ([]byte, error) {
	tpl, err := gs.parseTemplate("updatePassword", "updatePassword.html")
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		AlertMessage string
	}{
		"password",
		alertMessage,
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
				htmlPage, err := gs.ListUsers(ctx, token, alertMessage)
				if err != nil {
					return []byte{}, err
				}
				return htmlPage, ErrConflict
			}
			return []byte{}, err
		}
	}
	return gs.ListUsers(ctx, token, "")
}

func (gs *uiService) ListUsers(ctx context.Context, token, alertMessage string) ([]byte, error) {
	tpl, err := gs.parseTemplate("users", "users.html")
	if err != nil {
		return []byte{}, err
	}
	pgm := sdk.PageMetadata{
		Offset:     uint64(0),
		Total:      uint64(100),
		Limit:      uint64(100),
		Visibility: "all",
	}
	users, err := gs.sdk.Users(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := gs.UserProfile(ctx, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		Users        []sdk.User
		AlertMessage string
		User         sdk.User
	}{
		"users",
		users.Users,
		alertMessage,
		user,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "users", data); err != nil {
		println(err.Error())
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) ViewUser(ctx context.Context, token, userID string) ([]byte, error) {
	tpl, err := gs.parseTemplate("user", "user.html")
	if err != nil {
		return []byte{}, err
	}
	user, err := gs.sdk.User(userID, token)
	if err != nil {
		return []byte{}, err
	}
	loggedUser, err := gs.UserProfile(ctx, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		ID           string
		User         sdk.User
		LoggedUser   sdk.User
	}{
		"user",
		userID,
		user,
		loggedUser,
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
				htmlPage, err := gs.ListThings(ctx, token, alertMessage)
				if err != nil {
					return []byte{}, err
				}
				return htmlPage, ErrConflict
			}
			return []byte{}, err
		}
	}
	return gs.ListThings(ctx, token, "")
}

func (gs *uiService) ListThings(ctx context.Context, token, alertMessage string) ([]byte, error) {
	tpl, err := gs.parseTemplate("things", "things.html")
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

	user, err := gs.UserProfile(ctx, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		Things       []sdk.Thing
		AlertMessage string
		User         sdk.User
	}{
		"things",
		things.Things,
		alertMessage,
		user,
	}
	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "things", data); err != nil {
		println(err.Error())
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) ViewThing(ctx context.Context, token, id string) ([]byte, error) {
	tpl, err := gs.parseTemplate("thing", "thing.html")
	if err != nil {
		return []byte{}, err
	}
	thing, err := gs.sdk.Thing(id, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := gs.UserProfile(ctx, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		ID           string
		Thing        sdk.Thing
		User         sdk.User
	}{
		"thing",
		id,
		thing,
		user,
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
				htmlPage, err := gs.ListChannels(ctx, token, alertMessage)
				if err != nil {
					return []byte{}, err
				}
				return htmlPage, ErrConflict
			}
			return []byte{}, err
		}
	}
	return gs.ListChannels(ctx, token, "")
}

func (gs *uiService) ListChannels(ctx context.Context, token, alertMessage string) ([]byte, error) {
	tpl, err := gs.parseTemplate("channels", "channels.html")
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

	user, err := gs.UserProfile(ctx, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		Channels     []sdk.Channel
		AlertMessage string
		User         sdk.User
	}{
		"channels",
		chsPage.Channels,
		alertMessage,
		user,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "channels", data); err != nil {
		println(err.Error())
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) ViewChannel(ctx context.Context, token, id string) ([]byte, error) {
	tpl, err := gs.parseTemplate("channel", "channel.html")
	if err != nil {
		return []byte{}, err
	}

	channel, err := gs.sdk.Channel(id, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := gs.UserProfile(ctx, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		ID           string
		Channel      sdk.Channel
		User         sdk.User
	}{
		"channels",
		id,
		channel,
		user,
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
	tpl, err := gs.parseTemplate("thingconn", "thingconn.html")
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

	user, err := gs.UserProfile(ctx, token)
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
		User         sdk.User
	}{
		"things",
		id,
		thing,
		chsPage.Channels,
		allchsPage.Channels,
		plcPage.Policies,
		user,
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
	tpl, err := gs.parseTemplate("channelconn", "channelconn.html")
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
	tpl, err := gs.parseTemplate("thingsPolicies", "thingsPolicies.html")
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
		Actions      []string
	}{
		"thingsPolicies",
		plcPage.Policies,
		chsPage.Channels,
		thsPage.Things,
		thingActions,
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
	tpl, err := gs.parseTemplate("groupconn", "groupconn.html")
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

	user, err := gs.UserProfile(ctx, token)
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
		User         sdk.User
		Actions      []string
	}{
		"groups",
		id,
		group,
		members.Members,
		users.Users,
		plcPage.Policies,
		user,
		userActions,
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
				htmlPage, err := gs.ListGroups(ctx, token, alertMessage)
				if err != nil {
					return []byte{}, err
				}
				return htmlPage, ErrConflict
			}
			return []byte{}, err
		}
	}
	return gs.ListGroups(ctx, token, "")
}

func (gs *uiService) ListGroups(ctx context.Context, token, alertMessage string) ([]byte, error) {
	tpl, err := gs.parseTemplate("groups", "groups.html")
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

	user, err := gs.UserProfile(ctx, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		Groups       []sdk.Group
		AlertMessage string
		User         sdk.User
	}{
		"groups",
		grpPage.Groups,
		alertMessage,
		user,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "groups", data); err != nil {
		println(err.Error())
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) ViewGroup(ctx context.Context, token, id string) ([]byte, error) {
	tpl, err := gs.parseTemplate("group", "group.html")
	if err != nil {
		return []byte{}, err
	}

	group, err := gs.sdk.Group(id, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := gs.UserProfile(ctx, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		ID           string
		Group        sdk.Group
		User         sdk.User
	}{
		"groups",
		id,
		group,
		user,
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
	tpl, err := gs.parseTemplate("policies", "usersPolicies.html")
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
		Actions      []string
	}{
		"policies",
		plcPage.Policies,
		grpPage.Groups,
		users.Users,
		userActions,
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
	tpl, err := gs.parseTemplate("messagesread", "messagesread.html")
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
	tpl, err := gs.parseTemplate("messagesread", "messagesread.html")
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
	tpl, err := gs.parseTemplate("deletedClients", "deletedClients.html")
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

func (us *uiService) GetRemoteTerminal(ctx context.Context, id string) ([]byte, error) {
	tmpl, err := us.parseTemplate("remoteTerminal", "terminal.html")
	if err != nil {
		return []byte{}, err
	}
	data := struct {
		NavbarActive string
		ThingID      string
	}{
		NavbarActive: "bootstraps",
		ThingID:      id,
	}
	var btpl bytes.Buffer
	if err := tmpl.ExecuteTemplate(&btpl, "remoteTerminal", data); err != nil {
		println(err.Error())
	}

	return btpl.Bytes(), nil
}

func (us *uiService) ProcessTerminalCommand(ctx context.Context, id, tkn, command string, res chan string) error {
	cfg, err := us.sdk.ViewBootstrap(id, tkn)
	if err != nil {
		return err
	}

	var content bootstrap.ServicesConfig

	if err := json.Unmarshal([]byte(cfg.Content), &content); err != nil {
		return err
	}

	channels, ok := cfg.Channels.([]sdk.Channel)
	if !ok {
		return errors.New("invalid channels")
	}

	pubTopic := fmt.Sprintf("channels/%s/messages/req", channels[0].ID)
	subTopic := fmt.Sprintf("channels/%s/messages/res/#", channels[0].ID)

	opts := mqtt.NewClientOptions().SetCleanSession(true).SetAutoReconnect(true)

	opts.AddBroker(content.Agent.MQTT.URL)
	if content.Agent.MQTT.Username == "" || content.Agent.MQTT.Password == "" {
		opts.SetUsername(cfg.ThingID)
		opts.SetPassword(cfg.ThingKey)
	} else {
		opts.SetUsername(content.Agent.MQTT.Username)
		opts.SetPassword(content.Agent.MQTT.Password)
	}

	opts.SetClientID(fmt.Sprintf("ui-terminal-%s", cfg.ThingID))
	client := mqtt.NewClient(opts)

	if token := client.Connect(); token.Wait() && token.Error() != nil {
		return token.Error()
	}

	req := []senml.Record{
		{BaseName: "1", Name: "exec", StringValue: &command},
	}
	reqByte, err1 := json.Marshal(req)
	if err1 != nil {
		return err1
	}

	token := client.Publish(pubTopic, 0, false, string(reqByte))
	token.Wait()

	if token.Error() != nil {
		return token.Error()
	}

	var wg sync.WaitGroup
	wg.Add(1)
	errChan := make(chan error)

	client.Subscribe(subTopic, 0, func(c mqtt.Client, m mqtt.Message) {
		var data []senml.Record
		if err := json.Unmarshal(m.Payload(), &data); err != nil {
			errChan <- err
		}
		res <- *data[0].StringValue
		wg.Done()
	})

	select {
	case <-ctx.Done():
		log.Println("ProcessTerminalCommand canceled")
	case <-time.After(time.Second * 5):
		log.Println("Timeout occurred")
		res <- "timeout"
	case err := <-errChan:
		return err
	case <-res:
		wg.Wait()
	}

	client.Disconnect(250)
	return nil
}

func (us *uiService) ListBootstrap(ctx context.Context, token string) ([]byte, error) {
	tpl, err := us.parseTemplate("bootstraps", "bootstraps.html")
	if err != nil {
		return []byte{}, err
	}
	filter := sdk.PageMetadata{
		Offset: uint64(0),
		Total:  uint64(100),
		Limit:  uint64(100),
	}
	bootstraps, err := us.sdk.Bootstraps(filter, token)
	if err != nil {
		return []byte{}, err
	}

	things, err := us.sdk.Things(filter, token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		Bootstraps   []sdk.BootstrapConfig
		Things       []sdk.Thing
	}{
		"bootstraps",
		bootstraps.Configs,
		things.Things,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "bootstraps", data); err != nil {
		println(err.Error())
	}

	return btpl.Bytes(), nil
}
func (us *uiService) ViewBootstrap(ctx context.Context, token, id string) ([]byte, error) {
	tpl, err := us.parseTemplate("bootstrap", "bootstrap.html")
	if err != nil {
		return []byte{}, err
	}

	bootstrap, err := us.sdk.ViewBootstrap(id, token)
	if err != nil {
		return []byte{}, err
	}

	switch channels := bootstrap.Channels.(type) {
	case []sdk.Channel:
		var strChannels []string
		for _, chann := range channels {
			strChannels = append(strChannels, chann.ID)
		}
		bootstrap.Channels = strChannels
	case []string:
		bootstrap.Channels = channels
	case nil:
		bootstrap.Channels = []string{}
	default:
		return nil, errors.New("invalid channels")
	}

	data := struct {
		NavbarActive string
		Bootstrap    sdk.BootstrapConfig
	}{
		"bootstraps",
		bootstrap,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "bootstrap", data); err != nil {
		println(err.Error())
	}

	return btpl.Bytes(), nil
}

func (us *uiService) CreateBootstrap(ctx context.Context, token string, configs ...sdk.BootstrapConfig) ([]byte, error) {
	for _, cfg := range configs {
		_, err := us.sdk.AddBootstrap(cfg, token)
		if err != nil {
			return []byte{}, err
		}
	}
	return us.ListBootstrap(ctx, token)
}

func (us *uiService) DeleteBootstrap(ctx context.Context, token, id string) ([]byte, error) {
	if err := us.sdk.RemoveBootstrap(id, token); err != nil {
		return []byte{}, err
	}

	return us.ListBootstrap(ctx, token)
}

func (us *uiService) UpdateBootstrap(ctx context.Context, token string, config sdk.BootstrapConfig) ([]byte, error) {
	if err := us.sdk.UpdateBootstrap(config, token); err != nil {
		return []byte{}, err
	}

	return us.ViewBootstrap(ctx, token, config.ThingID)
}

func (us *uiService) UpdateBootstrapCerts(ctx context.Context, token string, config sdk.BootstrapConfig) ([]byte, error) {
	if _, err := us.sdk.UpdateBootstrapCerts(config.ThingID, config.ClientCert, config.ClientKey, config.CACert, token); err != nil {
		return []byte{}, err
	}

	return us.ViewBootstrap(ctx, token, config.ThingID)
}

func (us *uiService) UpdateBootstrapConnections(ctx context.Context, token string, config sdk.BootstrapConfig) ([]byte, error) {
	channels, ok := config.Channels.([]string)
	if !ok {
		return nil, errors.New("invalid channel")
	}
	if err := us.sdk.UpdateBootstrapConnection(config.ThingID, channels, token); err != nil {
		return []byte{}, err
	}

	return us.ViewBootstrap(ctx, token, config.ThingID)
}
