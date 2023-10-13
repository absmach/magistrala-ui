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
	"math"
	"strings"
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
	enabled     = "enabled"
	disabled    = "disabled"
	statusAll   = "all"
)

type dataSummary struct {
	TotalUsers       int
	TotalGroups      int
	EnabledUsers     int
	DisabledUsers    int
	EnabledGroups    int
	DisabledGroups   int
	EnabledThings    int
	DisabledThings   int
	EnabledChannels  int
	DisabledChannels int
	TotalThings      int
	TotalChannels    int
}

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

	tmplFiles    = []string{"header.html", "footer.html", "navbar.html", "tableheader.html", "tablefooter.html"}
	userActions  = []string{"g_list", "g_update", "g_delete", "g_add", "c_list", "c_update", "c_delete"}
	thingActions = []string{"m_read", "m_write"}
)

// Service specifies service API.
type Service interface {
	// Index displays the landing page of the UI.
	Index(token string) ([]byte, error)
	// Login displays the login page.
	Login() ([]byte, error)
	// Logout deletes the access token and refresh token from the cookies and logs the user out of the UI.
	Logout() error
	// PasswordResetRequest sends an email with a link to the password reset page with a valid request token.
	PasswordResetRequest(email string) error
	// PasswordReset resets the user's password.
	PasswordReset(token, password, confirmPass string) error
	// ShowPasswordReset displays the password reset page.
	ShowPasswordReset() ([]byte, error)
	// PasswordUpdate displays the password update page.
	PasswordUpdate() ([]byte, error)
	// UpdatePassword updates the user's old password to the new password.
	UpdatePassword(token, oldPass, newPass string) error
	// UserProfile retrieves information about the logged in user.
	UserProfile(token string) (sdk.User, error)
	// Token provides a user with an access token and a refresh token.
	Token(user sdk.User) (sdk.Token, error)
	// RefreshToken retrieves a new access token and refresh token from the provided refresh token.
	RefreshToken(refreshToken string) (sdk.Token, error)
	// CreateUsers creates new users.
	CreateUsers(token string, users ...sdk.User) error
	// ListUsers retrieves users owned/shared by a user.
	ListUsers(token string, page, limit uint64) ([]byte, error)
	// ViewUser retrieves information about the user with the given ID.
	ViewUser(token, userID string) ([]byte, error)
	// UpdateUser updates the user with the given ID.
	UpdateUser(token, userID string, user sdk.User) error
	// UpdateUserTags updates the tags of the user with the given ID.
	UpdateUserTags(token, userID string, user sdk.User) error
	// UpdateUserIdentity updates the identity of the user with the given ID.
	UpdateUserIdentity(token, userID string, user sdk.User) error
	// UpdateUserOwner updates the owner of the user with the given ID.
	UpdateUserOwner(token, userID string, user sdk.User) error
	// EnableUser updates the status of a user with the given ID to enabled.
	EnableUser(token, userID string) error
	// DisableUser updates the status of a user with the given ID to disabled.
	DisableUser(token, userID string) error
	// CreateThings creates new things.
	CreateThings(token string, things ...sdk.Thing) error
	// ListThings retrieves things owned/shared by a user.
	ListThings(token string, page, limit uint64) ([]byte, error)
	// ViewThing retrieves information about the thing with the given ID.
	ViewThing(token, id string) ([]byte, error)
	// UpdateThing updates the thing with the given ID.
	UpdateThing(token, id string, thing sdk.Thing) error
	// UpdateThingTags updates the tags of the thing with the given ID.
	UpdateThingTags(token, id string, thing sdk.Thing) error
	// UpdateThingSecret updates the secret of the thing with the given ID.
	UpdateThingSecret(token, id, secret string) error
	// UpdateThingOwner updates the owner of the thing with the given ID
	UpdateThingOwner(token string, thing sdk.Thing) error
	// EnableThing updates the status of the thing with the given ID to enabled.
	EnableThing(token, id string) error
	// DisableThing updates the status of the thing with the given ID to disabled
	DisableThing(token, id string) error
	// CreateChannels creates new channels.
	CreateChannels(token string, channels ...sdk.Channel) error
	// ListChannels retrieves channels owned/shared by a user.
	ListChannels(token string, page, limit uint64) ([]byte, error)
	// ViewChannel retrievs information about the channel with the given ID.
	ViewChannel(token, id string) ([]byte, error)
	// UpdateChannel updates the channel with the given ID.
	UpdateChannel(token, id string, channel sdk.Channel) error
	// ListChannelsByThing retrieves a list of channels based on the given thing ID.
	ListChannelsByThing(token, id string, page, limit uint64) ([]byte, error)
	// ListThingsByChannel retrieves a list of things based on the given channel ID.
	ListThingsByChannel(token, id string, page, limit uint64) ([]byte, error)
	// EnableChannel updates the status of the channel with the given ID to enabled.
	EnableChannel(token, id string) error
	// DisableChannel updates the status of the channel with the given ID to disabled.
	DisableChannel(token, id string) error
	// Connect bulk connects things to channel(s) specified by ID.
	Connect(token string, connIDs sdk.ConnectionIDs) error
	// Disconnect bulk disconnects thinfs to channel(s) specified by ID.
	Disconnect(token string, connIDs sdk.ConnectionIDs) error
	// ConnectThing connects a thing to a channel specified by ID.
	ConnectThing(token string, connIDs sdk.ConnectionIDs) error
	// ShareThing shares things connected to a channel with a user
	ShareThing(token, chanID, userID string, actions []string) error
	// DisconnectThing disconnects a thing from a channel specified by ID.
	DisconnectThing(thID, chID, token string) error
	// Connect Channel connects a channel to a thing specified by ID.
	ConnectChannel(token string, connIDs sdk.ConnectionIDs) error
	// DisconnectChannel disconnects a channel from a thing specified by ID.
	DisconnectChannel(thID, chID, token string) error
	// AddThingsPolicy adds a thing's policy on a channel.
	AddThingsPolicy(token string, Policy sdk.Policy) error
	// DeleteThingsPolicy removes a thing's policy on a channel
	DeleteThingsPolicy(token string, policy sdk.Policy) error
	// ListThingsPolicies retrieves the policies of things.
	ListThingsPolicies(token string, page, limit uint64) ([]byte, error)
	// UpdateThingsPolicy updates the policy that a thing has over a channel.
	UpdateThingsPolicy(token string, policy sdk.Policy) error
	// CreateGroups creates new groups.
	CreateGroups(token string, groups ...sdk.Group) error
	// ListGroupMembers retrieves the members of a group with a given ID.
	ListGroupMembers(token, id string, page, limit uint64) ([]byte, error)
	// Assign adds a user to a group.
	Assign(token, groupID, memberID string, memberType []string) error
	// Unassign removes a user from a group.
	Unassign(token, groupID, memberID string) error
	// ViewGroup retrieves information about a group with a given ID.
	ViewGroup(token, id string) ([]byte, error)
	// UpdateGroup updates the group with the given ID.
	UpdateGroup(token, id string, group sdk.Group) error
	// ListGroups retrieves the groups owned/shared by a user.
	ListGroups(token string, page, limit uint64) ([]byte, error)
	// EnableGroup updates the status of the group to enabled.
	EnableGroup(token, id string) error
	// DisableGroup updates the status of the group to disabled.
	DisableGroup(token, id string) error
	// AddPolicy adds a user's policy on a group effectively adding the user to the group.
	AddPolicy(token string, policy sdk.Policy) error
	// UpdatePolicy updates the policy a user has over a group.
	UpdatePolicy(token string, policy sdk.Policy) error
	// ListPolicies retrieves the policies of the users.
	ListPolicies(token string, page, limit uint64) ([]byte, error)
	// DeletePolicy removes a user's policies on a group effectively removing the user from the group.
	DeletePolicy(token string, policy sdk.Policy) error
	// Publish facilitates a thing publishin messages to a channel.
	Publish(token, thKey string, msg *messaging.Message) error
	// ReadMessage facilitates a thing reading messages published in a channel.
	ReadMessage(token string) ([]byte, error)
	// WsConnection creates a web socket connection that allows continuous reading of messages published in a channel.
	WsConnection(token, chID, thKey string) ([]byte, error)
	// CreateBootstrap creates a new bootstrap config.
	CreateBootstrap(token string, config ...sdk.BootstrapConfig) error
	// ListBootstrap retrieves all bootstrap configs.
	ListBootstrap(token string, page, limit uint64) ([]byte, error)
	// UpdateBootstrap allows update of bootstrap name and content.
	UpdateBootstrap(token string, config sdk.BootstrapConfig) error
	// UpdateBootstrapConnections updates connected channels on bootstrap configs.
	UpdateBootstrapConnections(token string, config sdk.BootstrapConfig) error
	// UpdateBootstrapCerts updates bootstrap certs.
	UpdateBootstrapCerts(token string, config sdk.BootstrapConfig) error
	// DeleteBootstrap deletes bootstrap config given an id.
	DeleteBootstrap(token, id string) error
	// ViewBootstrap retrieves a bootstrap config by thing id.
	ViewBootstrap(token, id string) ([]byte, error)
	// GetRemoteTerminal returns remote terminal for a bootstrap config with mainflux agent installed.
	GetRemoteTerminal(id string) ([]byte, error)
	// ProcessTerminalCommand sends mqtt command to agent and retrieves a response asynchronously.
	ProcessTerminalCommand(ctx context.Context, id, token, command string, res chan string) error
	GetEntities(token, item, name string, page, limit uint64) ([]byte, error)
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
			if data == nil {
				return "{}"
			}
			ret, err := json.Marshal(data)
			if err != nil {
				return "{}"
			}
			return string(ret)
		},
		"toSlice": func(data []string) string {
			if len(data) == 0 {
				return "[]"
			}
			ret, err := json.Marshal(data)
			if err != nil {
				return "[]"
			}
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
		"serviceUnavailable": func(service string) bool {
			if _, err := gs.sdk.Health(service); err != nil {
				return true
			}
			return false
		},
		"hasPrefix": func(s, prefix string) bool {
			return strings.HasPrefix(s, prefix)
		},
		"sub": func(num1, num2 int) int {
			return num1 - num2
		},
		"add": func(num1, num2 int) int {
			return num1 + num2
		},
		"max": func(a, b int) int {
			if a > b {
				return a
			}
			return b
		},
		"min": func(a, b int) int {
			if a < b {
				return a
			}
			return b
		},
		"fromTo": func(start, end int) []int {
			var result []int
			for i := start; i <= end; i++ {
				result = append(result, i)
			}
			return result
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

func (gs *uiService) Index(token string) ([]byte, error) {
	tpl, err := gs.parseTemplate("index", "index.html")
	if err != nil {
		return []byte{}, err
	}

	pgm := sdk.PageMetadata{
		Offset:     uint64(0),
		Visibility: statusAll,
		Status:     statusAll,
	}

	enabledPgm := sdk.PageMetadata{
		Offset:     uint64(0),
		Visibility: statusAll,
		Status:     enabled,
	}

	users, err := gs.sdk.Users(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	things, err := gs.sdk.Things(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	groups, err := gs.sdk.Groups(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	channels, err := gs.sdk.Channels(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	enabledUsers, err := gs.sdk.Users(enabledPgm, token)
	if err != nil {
		return []byte{}, err
	}

	enabledThings, err := gs.sdk.Things(enabledPgm, token)
	if err != nil {
		return []byte{}, err
	}

	enabledGroups, err := gs.sdk.Groups(enabledPgm, token)
	if err != nil {
		return []byte{}, err
	}

	enabledChannels, err := gs.sdk.Channels(enabledPgm, token)
	if err != nil {
		return []byte{}, err
	}

	var summary = dataSummary{
		TotalUsers:       int(users.Total),
		TotalGroups:      int(groups.Total),
		TotalThings:      int(things.Total),
		TotalChannels:    int(channels.Total),
		EnabledUsers:     int(enabledUsers.Total),
		DisabledUsers:    int(users.Total - enabledUsers.Total),
		EnabledGroups:    int(enabledGroups.Total),
		DisabledGroups:   int(groups.Total - enabledGroups.Total),
		EnabledThings:    int(enabledThings.Total),
		DisabledThings:   int(things.Total - enabledThings.Total),
		EnabledChannels:  int(enabledChannels.Total),
		DisabledChannels: int(channels.Total - enabledChannels.Total),
	}

	user, err := gs.UserProfile(token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		User         sdk.User
		Summary      dataSummary
	}{
		"dashboard",
		user,
		summary,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "index", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) Login() ([]byte, error) {
	tpl, err := gs.parseTemplate("login", "login.html")
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
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) PasswordResetRequest(email string) error {

	return gs.sdk.ResetPasswordRequest(email)
}

func (gs *uiService) PasswordReset(token, password, confirmPass string) error {
	return gs.sdk.ResetPassword(token, password, confirmPass)
}

func (gs *uiService) ShowPasswordReset() ([]byte, error) {
	tpl, err := gs.parseTemplate("resetPassword", "resetPassword.html")
	if err != nil {
		return []byte{}, err
	}
	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "resetPassword", ""); err != nil {
		return []byte{}, err
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) PasswordUpdate() ([]byte, error) {
	tpl, err := gs.parseTemplate("updatePassword", "updatePassword.html")
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
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) Token(user sdk.User) (sdk.Token, error) {
	token, err := gs.sdk.CreateToken(user)
	if err != nil {
		return sdk.Token{}, err
	}
	return token, nil
}

func (gs *uiService) RefreshToken(refreshToken string) (sdk.Token, error) {
	token, err := gs.sdk.RefreshToken(refreshToken)
	if err != nil {
		return sdk.Token{}, err
	}
	return token, nil
}

func (gs *uiService) Logout() error {
	return nil
}

func (gs *uiService) UserProfile(token string) (sdk.User, error) {
	user, err := gs.sdk.UserProfile(token)
	if err != nil {
		return sdk.User{}, err
	}

	return user, nil
}

func (gs *uiService) UpdatePassword(token, oldPass, newPass string) error {
	_, err := gs.sdk.UpdatePassword(oldPass, newPass, token)
	return err
}

func (gs *uiService) CreateUsers(token string, users ...sdk.User) error {
	for i := range users {
		_, err := gs.sdk.CreateUser(users[i], token)
		if err != nil {
			return err
		}
	}
	return nil
}

func (gs *uiService) ListUsers(token string, page, limit uint64) ([]byte, error) {
	tpl, err := gs.parseTemplate("users", "users.html")
	if err != nil {
		return []byte{}, err
	}
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}
	users, err := gs.sdk.Users(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := gs.UserProfile(token)
	if err != nil {
		return []byte{}, err
	}
	noOfPages := int(math.Ceil(float64(users.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		Users        []sdk.User
		User         sdk.User
		CurrentPage  int
		Pages        int
		Limit        int
	}{
		"users",
		users.Users,
		user,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "users", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) ViewUser(token, userID string) ([]byte, error) {
	tpl, err := gs.parseTemplate("user", "user.html")
	if err != nil {
		return []byte{}, err
	}
	user, err := gs.sdk.User(userID, token)
	if err != nil {
		return []byte{}, err
	}
	loggedUser, err := gs.UserProfile(token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		ID           string
		User         sdk.User
		LoggedUser   sdk.User
	}{
		"users",
		userID,
		user,
		loggedUser,
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "user", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) UpdateUser(token, userID string, user sdk.User) error {
	_, err := gs.sdk.UpdateUser(user, token)

	return err
}

func (gs *uiService) UpdateUserTags(token, userID string, user sdk.User) error {
	_, err := gs.sdk.UpdateUserTags(user, token)

	return err
}

func (gs *uiService) UpdateUserIdentity(token, userID string, user sdk.User) error {
	_, err := gs.sdk.UpdateUserIdentity(user, token)

	return err
}

func (gs *uiService) UpdateUserOwner(token, userID string, user sdk.User) error {
	_, err := gs.sdk.UpdateUserIdentity(user, token)

	return err
}

func (gs *uiService) EnableUser(token, userID string) error {
	_, err := gs.sdk.EnableUser(userID, token)

	return err
}

func (gs *uiService) DisableUser(token, userID string) error {
	_, err := gs.sdk.DisableUser(userID, token)

	return err
}

func (gs *uiService) CreateThings(token string, things ...sdk.Thing) error {
	for _, thing := range things {
		_, err := gs.sdk.CreateThing(thing, token)
		if err != nil {
			return err
		}
	}
	return nil
}

func (gs *uiService) ListThings(token string, page, limit uint64) ([]byte, error) {
	tpl, err := gs.parseTemplate("things", "things.html")
	if err != nil {
		return []byte{}, err
	}
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}

	things, err := gs.sdk.Things(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := gs.UserProfile(token)
	if err != nil {
		return []byte{}, err
	}
	noOfPages := int(math.Ceil(float64(things.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		Things       []sdk.Thing
		User         sdk.User
		CurrentPage  int
		Pages        int
		Limit        int
	}{
		"things",
		things.Things,
		user,
		int(page),
		noOfPages,
		int(limit),
	}
	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "things", data); err != nil {
		return []byte{}, err
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) ViewThing(token, id string) ([]byte, error) {
	tpl, err := gs.parseTemplate("thing", "thing.html")
	if err != nil {
		return []byte{}, err
	}
	thing, err := gs.sdk.Thing(id, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := gs.UserProfile(token)
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
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) UpdateThing(token, id string, thing sdk.Thing) error {
	_, err := gs.sdk.UpdateThing(thing, token)

	return err
}

func (gs *uiService) UpdateThingTags(token, id string, thing sdk.Thing) error {
	_, err := gs.sdk.UpdateThingTags(thing, token)

	return err
}

func (gs *uiService) UpdateThingSecret(token, id, secret string) error {
	_, err := gs.sdk.UpdateThingSecret(id, secret, token)

	return err
}

func (gs *uiService) UpdateThingOwner(token string, thing sdk.Thing) error {
	_, err := gs.sdk.UpdateThingOwner(thing, token)

	return err
}

func (gs *uiService) EnableThing(token, id string) error {
	_, err := gs.sdk.EnableThing(id, token)

	return err
}

func (gs *uiService) DisableThing(token, id string) error {
	_, err := gs.sdk.DisableThing(id, token)

	return err
}

func (gs *uiService) CreateChannels(token string, channels ...sdk.Channel) error {
	for _, channel := range channels {
		_, err := gs.sdk.CreateChannel(channel, token)
		if err != nil {
			return err
		}
	}
	return nil
}

func (gs *uiService) ListChannels(token string, page, limit uint64) ([]byte, error) {
	tpl, err := gs.parseTemplate("channels", "channels.html")
	if err != nil {
		return []byte{}, err
	}

	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}
	chsPage, err := gs.sdk.Channels(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := gs.UserProfile(token)
	if err != nil {
		return []byte{}, err
	}
	noOfPages := int(math.Ceil(float64(chsPage.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		Channels     []sdk.Channel
		User         sdk.User
		CurrentPage  int
		Pages        int
		Limit        int
	}{
		"channels",
		chsPage.Channels,
		user,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "channels", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) ViewChannel(token, id string) ([]byte, error) {
	tpl, err := gs.parseTemplate("channel", "channel.html")
	if err != nil {
		return []byte{}, err
	}

	channel, err := gs.sdk.Channel(id, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := gs.UserProfile(token)
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
		return []byte{}, err
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) UpdateChannel(token, id string, channel sdk.Channel) error {
	_, err := gs.sdk.UpdateChannel(channel, token)

	return err
}

func (gs *uiService) EnableChannel(token, id string) error {
	_, err := gs.sdk.EnableChannel(id, token)

	return err
}

func (gs *uiService) DisableChannel(token, id string) error {
	_, err := gs.sdk.DisableChannel(id, token)

	return err
}

func (gs *uiService) ConnectThing(token string, connIDs sdk.ConnectionIDs) error {

	return gs.sdk.Connect(connIDs, token)
}

func (gs *uiService) ShareThing(token, chanID, userID string, actions []string) error {

	return gs.sdk.ShareThing(chanID, userID, actions, token)

}

func (gs *uiService) DisconnectThing(thID, chID, token string) error {

	return gs.sdk.DisconnectThing(thID, chID, token)

}

func (gs *uiService) ConnectChannel(token string, connIDs sdk.ConnectionIDs) error {

	return gs.sdk.Connect(connIDs, token)

}

func (gs *uiService) DisconnectChannel(thID, chID, token string) error {

	return gs.sdk.DisconnectThing(thID, chID, token)

}

func (gs *uiService) ListChannelsByThing(token, id string, page, limit uint64) ([]byte, error) {
	tpl, err := gs.parseTemplate("thingconn", "thingconn.html")
	if err != nil {
		return []byte{}, err
	}

	thing, err := gs.sdk.Thing(id, token)
	if err != nil {
		return []byte{}, err
	}
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}

	chsPage, err := gs.sdk.ChannelsByThing(id, pgm, token)
	if err != nil {
		return []byte{}, err
	}

	filter := sdk.PageMetadata{
		Offset: uint64(0),
		Total:  uint64(100),
		Limit:  uint64(100),
	}

	allchsPage, err := gs.sdk.Channels(filter, token)
	if err != nil {
		return []byte{}, err
	}

	plcPage, err := gs.sdk.ListThingPolicies(filter, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := gs.UserProfile(token)
	if err != nil {
		return []byte{}, err
	}
	noOfPages := int(math.Ceil(float64(chsPage.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		ID           string
		Thing        sdk.Thing
		Channels     []sdk.Channel
		AllChannels  []sdk.Channel
		Policies     []sdk.Policy
		User         sdk.User
		CurrentPage  int
		Pages        int
		Limit        int
	}{
		"things",
		id,
		thing,
		chsPage.Channels,
		allchsPage.Channels,
		plcPage.Policies,
		user,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "thingconn", data); err != nil {
		return []byte{}, err
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) Connect(token string, connIDs sdk.ConnectionIDs) error {

	return gs.sdk.Connect(connIDs, token)

}

func (gs *uiService) Disconnect(token string, connIDs sdk.ConnectionIDs) error {

	return gs.sdk.Disconnect(connIDs, token)
}

func (gs *uiService) ListThingsByChannel(token, id string, page, limit uint64) ([]byte, error) {
	tpl, err := gs.parseTemplate("channelconn", "channelconn.html")
	if err != nil {
		return []byte{}, err
	}

	channel, err := gs.sdk.Channel(id, token)
	if err != nil {
		return []byte{}, err
	}
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}

	thsPage, err := gs.sdk.ThingsByChannel(id, pgm, token)
	if err != nil {
		return []byte{}, err
	}

	filter := sdk.PageMetadata{
		Offset: uint64(0),
		Total:  uint64(100),
		Limit:  uint64(100),
	}

	allthsPage, err := gs.sdk.Things(filter, token)
	if err != nil {
		return []byte{}, err
	}

	plcPage, err := gs.sdk.ListThingPolicies(filter, token)
	if err != nil {
		return []byte{}, err
	}
	users, err := gs.sdk.Users(filter, token)
	if err != nil {
		return []byte{}, err
	}
	noOfPages := int(math.Ceil(float64(thsPage.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		ID           string
		Channel      sdk.Channel
		Things       []sdk.Thing
		AllThings    []sdk.Thing
		Policies     []sdk.Policy
		Users        []sdk.User
		CurrentPage  int
		Pages        int
		Limit        int
	}{
		"channels",
		id,
		channel,
		thsPage.Things,
		allthsPage.Things,
		plcPage.Policies,
		users.Users,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "channelconn", data); err != nil {
		return []byte{}, err
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) ListThingsPolicies(token string, page, limit uint64) ([]byte, error) {
	tpl, err := gs.parseTemplate("thingsPolicies", "thingsPolicies.html")
	if err != nil {
		return []byte{}, err
	}
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}
	plcPage, err := gs.sdk.ListThingPolicies(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	filter := sdk.PageMetadata{
		Offset: uint64(0),
		Total:  uint64(100),
		Limit:  uint64(100),
	}

	chsPage, err := gs.sdk.Channels(filter, token)
	if err != nil {
		return []byte{}, err
	}

	thsPage, err := gs.sdk.Things(filter, token)
	if err != nil {
		return []byte{}, err
	}
	noOfPages := int(math.Ceil(float64(plcPage.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		Policies     []sdk.Policy
		Channels     []sdk.Channel
		Things       []sdk.Thing
		Actions      []string
		CurrentPage  int
		Pages        int
		Limit        int
	}{
		"thingsPolicies",
		plcPage.Policies,
		chsPage.Channels,
		thsPage.Things,
		thingActions,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "thingsPolicies", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) AddThingsPolicy(token string, policy sdk.Policy) error {

	return gs.sdk.CreateThingPolicy(policy, token)

}

func (gs *uiService) DeleteThingsPolicy(token string, policy sdk.Policy) error {

	return gs.sdk.DeleteThingPolicy(policy, token)

}

func (gs *uiService) UpdateThingsPolicy(token string, policy sdk.Policy) error {

	return gs.sdk.UpdateThingPolicy(policy, token)

}

func (gs *uiService) ListGroupMembers(token, id string, page, limit uint64) ([]byte, error) {
	tpl, err := gs.parseTemplate("groupconn", "groupconn.html")
	if err != nil {
		return []byte{}, err
	}

	group, err := gs.sdk.Group(id, token)
	if err != nil {
		return []byte{}, err
	}
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}
	members, err := gs.sdk.Members(id, pgm, token)
	if err != nil {
		return []byte{}, err
	}

	filter := sdk.PageMetadata{
		Offset: uint64(0),
		Total:  uint64(100),
		Limit:  uint64(100),
	}

	user, err := gs.UserProfile(token)
	if err != nil {
		return []byte{}, err
	}

	users, err := gs.sdk.Users(filter, token)
	if err != nil {
		return []byte{}, err
	}

	plcPage, err := gs.sdk.ListUserPolicies(filter, token)
	if err != nil {
		return []byte{}, err
	}
	noOfPages := int(math.Ceil(float64(members.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		ID           string
		Group        sdk.Group
		Members      []sdk.User
		Users        []sdk.User
		Policies     []sdk.Policy
		User         sdk.User
		Actions      []string
		CurrentPage  int
		Pages        int
		Limit        int
	}{
		"groups",
		id,
		group,
		members.Members,
		users.Users,
		plcPage.Policies,
		user,
		userActions,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "groupconn", data); err != nil {
		return []byte{}, err
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) CreateGroups(token string, groups ...sdk.Group) error {
	for _, group := range groups {
		_, err := gs.sdk.CreateGroup(group, token)
		if err != nil {
			return err
		}
	}
	return nil
}

func (gs *uiService) ListGroups(token string, page, limit uint64) ([]byte, error) {
	tpl, err := gs.parseTemplate("groups", "groups.html")
	if err != nil {
		return []byte{}, err
	}
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}
	grpPage, err := gs.sdk.Groups(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := gs.UserProfile(token)
	if err != nil {
		return []byte{}, err
	}
	noOfPages := int(math.Ceil(float64(grpPage.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		Groups       []sdk.Group
		User         sdk.User
		CurrentPage  int
		Pages        int
		Limit        int
	}{
		"groups",
		grpPage.Groups,
		user,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "groups", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) ViewGroup(token, id string) ([]byte, error) {
	tpl, err := gs.parseTemplate("group", "group.html")
	if err != nil {
		return []byte{}, err
	}

	group, err := gs.sdk.Group(id, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := gs.UserProfile(token)
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
		return []byte{}, err
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) Assign(token, groupID, memberID string, memberType []string) error {

	return gs.sdk.Assign(memberType, memberID, groupID, token)

}

func (gs *uiService) Unassign(token, groupID, memberID string) error {

	return gs.sdk.Unassign(memberID, groupID, token)

}

func (gs *uiService) UpdateGroup(token, id string, group sdk.Group) error {
	_, err := gs.sdk.UpdateGroup(group, token)

	return err
}

func (gs *uiService) EnableGroup(token, id string) error {
	_, err := gs.sdk.EnableGroup(id, token)

	return err
}

func (gs *uiService) DisableGroup(token, id string) error {
	_, err := gs.sdk.DisableGroup(id, token)

	return err
}

func (gs *uiService) AddPolicy(token string, policy sdk.Policy) error {

	return gs.sdk.CreateUserPolicy(policy, token)

}

func (gs *uiService) ListPolicies(token string, page, limit uint64) ([]byte, error) {
	tpl, err := gs.parseTemplate("policies", "usersPolicies.html")
	if err != nil {
		return []byte{}, err
	}
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}
	plcPage, err := gs.sdk.ListUserPolicies(pgm, token)
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

	users, err := gs.sdk.Users(filter, token)
	if err != nil {
		return []byte{}, err
	}
	noOfPages := int(math.Ceil(float64(plcPage.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		Policies     []sdk.Policy
		Groups       []sdk.Group
		Users        []sdk.User
		Actions      []string
		CurrentPage  int
		Pages        int
		Limit        int
	}{
		"policies",
		plcPage.Policies,
		grpPage.Groups,
		users.Users,
		userActions,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "policies", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) UpdatePolicy(token string, policy sdk.Policy) error {

	return gs.sdk.UpdateUserPolicy(policy, token)

}

func (gs *uiService) DeletePolicy(token string, policy sdk.Policy) error {

	return gs.sdk.DeleteUserPolicy(policy, token)

}

func (gs *uiService) Publish(token, thKey string, msg *messaging.Message) error {

	return gs.sdk.SendMessage(msg.Channel, string(msg.Payload), thKey)

}

func (gs *uiService) ReadMessage(_ string) ([]byte, error) {
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
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) WsConnection(_, chID, thKey string) ([]byte, error) {
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
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (us *uiService) GetRemoteTerminal(id string) ([]byte, error) {
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
		return []byte{}, err
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

	client.Subscribe(subTopic, 0, func(_ mqtt.Client, m mqtt.Message) {
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

func (us *uiService) ListBootstrap(token string, page, limit uint64) ([]byte, error) {
	tpl, err := us.parseTemplate("bootstraps", "bootstraps.html")
	if err != nil {
		return []byte{}, err
	}
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}

	bootstraps, err := us.sdk.Bootstraps(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	filter := sdk.PageMetadata{
		Offset: uint64(0),
		Total:  uint64(100),
		Limit:  uint64(100),
	}

	things, err := us.sdk.Things(filter, token)
	if err != nil {
		return []byte{}, err
	}

	noOfPages := int(math.Ceil(float64(bootstraps.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		Bootstraps   []sdk.BootstrapConfig
		Things       []sdk.Thing
		CurrentPage  int
		Pages        int
		Limit        int
	}{
		"bootstraps",
		bootstraps.Configs,
		things.Things,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := tpl.ExecuteTemplate(&btpl, "bootstraps", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}
func (us *uiService) ViewBootstrap(token, id string) ([]byte, error) {
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
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (us *uiService) CreateBootstrap(token string, configs ...sdk.BootstrapConfig) error {
	for _, cfg := range configs {
		_, err := us.sdk.AddBootstrap(cfg, token)
		if err != nil {
			return err
		}
	}
	return nil
}

func (us *uiService) DeleteBootstrap(token, id string) error {

	return us.sdk.RemoveBootstrap(id, token)

}

func (us *uiService) UpdateBootstrap(token string, config sdk.BootstrapConfig) error {

	return us.sdk.UpdateBootstrap(config, token)

}

func (us *uiService) UpdateBootstrapCerts(token string, config sdk.BootstrapConfig) error {
	_, err := us.sdk.UpdateBootstrapCerts(config.ThingID, config.ClientCert, config.ClientKey, config.CACert, token)

	return err
}

func (us *uiService) UpdateBootstrapConnections(token string, config sdk.BootstrapConfig) error {
	channels, ok := config.Channels.([]string)
	if !ok {
		return errors.New("invalid channel")
	}
	return us.sdk.UpdateBootstrapConnection(config.ThingID, channels, token)

}

func (gs *uiService) GetEntities(token, item, name string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit
	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Name:       name,
		Visibility: statusAll,
	}
	var items = make(map[string]interface{})
	switch item {
	case "groups":
		groups, err := gs.sdk.Groups(pgm, token)
		if err != nil {
			return []byte{}, err
		}
		items["data"] = groups.Groups
	case "users":
		users, err := gs.sdk.Users(pgm, token)
		if err != nil {
			return []byte{}, err
		}
		items["data"] = users.Users
	case "things":
		things, err := gs.sdk.Things(pgm, token)
		if err != nil {
			return []byte{}, err
		}
		items["data"] = things.Things
	case "channels":
		channels, err := gs.sdk.Channels(pgm, token)
		if err != nil {
			return []byte{}, err
		}
		items["data"] = channels.Channels
	}

	jsonData, err := json.Marshal(items)
	if err != nil {
		return []byte{}, err
	}
	return jsonData, nil
}
