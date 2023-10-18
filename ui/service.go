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
	templateDir            = "ui/web/template"
	enabled                = "enabled"
	disabled               = "disabled"
	statusAll              = "all"
	dashboardActive        = "dashboard"
	usersActive            = "users"
	thingsActive           = "things"
	usersPoliciesActive    = "usersPolicies"
	groupsActive           = "groups"
	channelsActive         = "channels"
	thingsPoliciesActive   = "thingsPolicies"
	disabledEntitiesActive = "disabled"
	readMessagesActive     = "readmessages"
	bootstrapsActive       = "bootstraps"
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

	templates = []string{
		"header",
		"navbar",
		"footer",
		"tableheader",
		"tablefooter",

		"bootstrap",
		"bootstraps",
		"terminal",

		"channel",
		"channelconn",
		"channels",

		"group",
		"groupconn",
		"groups",

		"index",

		"login",
		"resetpassword",
		"updatepassword",

		"messagesread",

		"thing",
		"thingconn",
		"things",
		"thingspolicies",

		"user",
		"users",
		"userspolicies",
	}
	emptyData    = struct{}{}
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
	PasswordUpdate(token string) ([]byte, error)
	// UpdatePassword updates the user's old password to the new password.
	UpdatePassword(token, oldPass, newPass string) error
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
	GetRemoteTerminal(id, token string) ([]byte, error)
	// ProcessTerminalCommand sends mqtt command to agent and retrieves a response asynchronously.
	ProcessTerminalCommand(ctx context.Context, id, token, command string, res chan string) error
	GetEntities(token, item, name string, page, limit uint64) ([]byte, error)
}

var _ Service = (*uiService)(nil)

type uiService struct {
	sdk  sdk.SDK
	tpls *template.Template
}

// New instantiates the HTTP adapter implementation.
func New(sdk sdk.SDK) (Service, error) {
	tpl, err := parseTemplates(sdk, templates)
	if err != nil {
		return nil, err
	}
	return &uiService{
		sdk:  sdk,
		tpls: tpl,
	}, nil
}

func parseTemplates(mfsdk sdk.SDK, templates []string) (tpl *template.Template, err error) {
	tpl = template.New("mainflux")
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

			authorized, _ := mfsdk.AuthorizeUser(aReq, "")

			return authorized
		},
		"authorizeThing": func(subject, object, action, entityType string) bool {
			var aReq = sdk.AccessRequest{
				Subject:    subject,
				Object:     object,
				Action:     action,
				EntityType: entityType,
			}

			authorizeThing, _, _ := mfsdk.AuthorizeThing(aReq, "")

			return authorizeThing
		},
		"serviceUnavailable": func(service string) bool {
			if _, err := mfsdk.Health(service); err != nil {
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

	var tmplFiles []string
	for _, value := range templates {
		tmplFiles = append(tmplFiles, templateDir+"/"+value+".html")
	}
	tpl, err = tpl.ParseFiles(tmplFiles...)
	if err != nil {
		return nil, err
	}

	return tpl, nil
}

func (us *uiService) Index(token string) (b []byte, err error) {
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

	users, err := us.sdk.Users(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	things, err := us.sdk.Things(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	groups, err := us.sdk.Groups(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	channels, err := us.sdk.Channels(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	enabledUsers, err := us.sdk.Users(enabledPgm, token)
	if err != nil {
		return []byte{}, err
	}

	enabledThings, err := us.sdk.Things(enabledPgm, token)
	if err != nil {
		return []byte{}, err
	}

	enabledGroups, err := us.sdk.Groups(enabledPgm, token)
	if err != nil {
		return []byte{}, err
	}

	enabledChannels, err := us.sdk.Channels(enabledPgm, token)
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

	user, err := us.sdk.UserProfile(token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		User         sdk.User
		Summary      dataSummary
	}{
		dashboardActive,
		user,
		summary,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "index", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (us *uiService) Login() ([]byte, error) {
	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "login", emptyData); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (us *uiService) PasswordResetRequest(email string) error {

	return us.sdk.ResetPasswordRequest(email)
}

func (us *uiService) PasswordReset(token, password, confirmPass string) error {
	return us.sdk.ResetPassword(token, password, confirmPass)
}

func (us *uiService) ShowPasswordReset() ([]byte, error) {
	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "resetPassword", emptyData); err != nil {
		return []byte{}, err
	}
	return btpl.Bytes(), nil
}

func (us *uiService) PasswordUpdate(token string) ([]byte, error) {
	user, err := us.sdk.UserProfile(token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		User         sdk.User
	}{
		"password",
		user,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "updatePassword", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (us *uiService) Token(user sdk.User) (sdk.Token, error) {
	token, err := us.sdk.CreateToken(user)
	if err != nil {
		return sdk.Token{}, err
	}
	return token, nil
}

func (us *uiService) RefreshToken(refreshToken string) (sdk.Token, error) {
	token, err := us.sdk.RefreshToken(refreshToken)
	if err != nil {
		return sdk.Token{}, err
	}
	return token, nil
}

func (us *uiService) Logout() error {
	return nil
}

func (us *uiService) UpdatePassword(token, oldPass, newPass string) error {
	_, err := us.sdk.UpdatePassword(oldPass, newPass, token)
	return err
}

func (us *uiService) CreateUsers(token string, users ...sdk.User) error {
	for i := range users {
		_, err := us.sdk.CreateUser(users[i], token)
		if err != nil {
			return err
		}
	}
	return nil
}

func (us *uiService) ListUsers(token string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}
	users, err := us.sdk.Users(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := us.sdk.UserProfile(token)
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
		usersActive,
		users.Users,
		user,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "users", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (us *uiService) ViewUser(token, userID string) (b []byte, err error) {
	user, err := us.sdk.User(userID, token)
	if err != nil {
		return []byte{}, err
	}
	loggedUser, err := us.sdk.UserProfile(token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		ID           string
		User         sdk.User
		LoggedUser   sdk.User
	}{
		usersActive,
		userID,
		user,
		loggedUser,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "user", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (us *uiService) UpdateUser(token, userID string, user sdk.User) error {
	_, err := us.sdk.UpdateUser(user, token)

	return err
}

func (us *uiService) UpdateUserTags(token, userID string, user sdk.User) error {
	_, err := us.sdk.UpdateUserTags(user, token)

	return err
}

func (us *uiService) UpdateUserIdentity(token, userID string, user sdk.User) error {
	_, err := us.sdk.UpdateUserIdentity(user, token)

	return err
}

func (us *uiService) UpdateUserOwner(token, userID string, user sdk.User) error {
	_, err := us.sdk.UpdateUserIdentity(user, token)

	return err
}

func (us *uiService) EnableUser(token, userID string) error {
	_, err := us.sdk.EnableUser(userID, token)

	return err
}

func (us *uiService) DisableUser(token, userID string) error {
	_, err := us.sdk.DisableUser(userID, token)

	return err
}

func (us *uiService) CreateThings(token string, things ...sdk.Thing) error {
	for _, thing := range things {
		_, err := us.sdk.CreateThing(thing, token)
		if err != nil {
			return err
		}
	}
	return nil
}

func (us *uiService) ListThings(token string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}
	things, err := us.sdk.Things(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := us.sdk.UserProfile(token)
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
		thingsActive,
		things.Things,
		user,
		int(page),
		noOfPages,
		int(limit),
	}
	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "things", data); err != nil {
		return []byte{}, err
	}
	return btpl.Bytes(), nil
}

func (us *uiService) ViewThing(token, id string) (b []byte, err error) {
	thing, err := us.sdk.Thing(id, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := us.sdk.UserProfile(token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		ID           string
		Thing        sdk.Thing
		User         sdk.User
	}{
		thingsActive,
		id,
		thing,
		user,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "thing", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (us *uiService) UpdateThing(token, id string, thing sdk.Thing) error {
	_, err := us.sdk.UpdateThing(thing, token)

	return err
}

func (us *uiService) UpdateThingTags(token, id string, thing sdk.Thing) error {
	_, err := us.sdk.UpdateThingTags(thing, token)

	return err
}

func (us *uiService) UpdateThingSecret(token, id, secret string) error {
	_, err := us.sdk.UpdateThingSecret(id, secret, token)

	return err
}

func (us *uiService) UpdateThingOwner(token string, thing sdk.Thing) error {
	_, err := us.sdk.UpdateThingOwner(thing, token)

	return err
}

func (us *uiService) EnableThing(token, id string) error {
	_, err := us.sdk.EnableThing(id, token)

	return err
}

func (us *uiService) DisableThing(token, id string) error {
	_, err := us.sdk.DisableThing(id, token)

	return err
}

func (us *uiService) CreateChannels(token string, channels ...sdk.Channel) error {
	for _, channel := range channels {
		_, err := us.sdk.CreateChannel(channel, token)
		if err != nil {
			return err
		}
	}
	return nil
}

func (us *uiService) ListChannels(token string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}
	chsPage, err := us.sdk.Channels(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := us.sdk.UserProfile(token)
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
		channelsActive,
		chsPage.Channels,
		user,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "channels", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (us *uiService) ViewChannel(token, id string) (b []byte, err error) {
	channel, err := us.sdk.Channel(id, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := us.sdk.UserProfile(token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		ID           string
		Channel      sdk.Channel
		User         sdk.User
	}{
		channelsActive,
		id,
		channel,
		user,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "channel", data); err != nil {
		return []byte{}, err
	}
	return btpl.Bytes(), nil
}

func (us *uiService) UpdateChannel(token, id string, channel sdk.Channel) error {
	_, err := us.sdk.UpdateChannel(channel, token)

	return err
}

func (us *uiService) EnableChannel(token, id string) error {
	_, err := us.sdk.EnableChannel(id, token)

	return err
}

func (us *uiService) DisableChannel(token, id string) error {
	_, err := us.sdk.DisableChannel(id, token)

	return err
}

func (us *uiService) ConnectThing(token string, connIDs sdk.ConnectionIDs) error {

	return us.sdk.Connect(connIDs, token)
}

func (us *uiService) ShareThing(token, chanID, userID string, actions []string) error {

	return us.sdk.ShareThing(chanID, userID, actions, token)

}

func (us *uiService) DisconnectThing(thID, chID, token string) error {

	return us.sdk.DisconnectThing(thID, chID, token)

}

func (us *uiService) ConnectChannel(token string, connIDs sdk.ConnectionIDs) error {

	return us.sdk.Connect(connIDs, token)

}

func (us *uiService) DisconnectChannel(thID, chID, token string) error {

	return us.sdk.DisconnectThing(thID, chID, token)

}

func (us *uiService) ListChannelsByThing(token, id string, page, limit uint64) ([]byte, error) {
	thing, err := us.sdk.Thing(id, token)
	if err != nil {
		return []byte{}, err
	}
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}

	chsPage, err := us.sdk.ChannelsByThing(id, pgm, token)
	if err != nil {
		return []byte{}, err
	}

	allchsPage, err := us.sdk.Channels(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	plcPage, err := us.sdk.ListThingPolicies(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := us.sdk.UserProfile(token)
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
		thingsActive,
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
	if err := us.tpls.ExecuteTemplate(&btpl, "thingconn", data); err != nil {
		return []byte{}, err
	}
	return btpl.Bytes(), nil
}

func (us *uiService) Connect(token string, connIDs sdk.ConnectionIDs) error {

	return us.sdk.Connect(connIDs, token)

}

func (us *uiService) Disconnect(token string, connIDs sdk.ConnectionIDs) error {

	return us.sdk.Disconnect(connIDs, token)
}

func (us *uiService) ListThingsByChannel(token, id string, page, limit uint64) ([]byte, error) {
	channel, err := us.sdk.Channel(id, token)
	if err != nil {
		return []byte{}, err
	}
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}

	thsPage, err := us.sdk.ThingsByChannel(id, pgm, token)
	if err != nil {
		return []byte{}, err
	}

	allthsPage, err := us.sdk.Things(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	plcPage, err := us.sdk.ListThingPolicies(pgm, token)
	if err != nil {
		return []byte{}, err
	}
	users, err := us.sdk.Users(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := us.sdk.UserProfile(token)
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
		User         sdk.User
		CurrentPage  int
		Pages        int
		Limit        int
	}{
		channelsActive,
		id,
		channel,
		thsPage.Things,
		allthsPage.Things,
		plcPage.Policies,
		users.Users,
		user,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "channelconn", data); err != nil {
		return []byte{}, err
	}
	return btpl.Bytes(), nil
}

func (us *uiService) ListThingsPolicies(token string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}
	plcPage, err := us.sdk.ListThingPolicies(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	chsPage, err := us.sdk.Channels(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	thsPage, err := us.sdk.Things(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := us.sdk.UserProfile(token)
	if err != nil {
		return []byte{}, err
	}

	noOfPages := int(math.Ceil(float64(plcPage.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		Policies     []sdk.Policy
		Channels     []sdk.Channel
		Things       []sdk.Thing
		User         sdk.User
		Actions      []string
		CurrentPage  int
		Pages        int
		Limit        int
	}{
		thingsPoliciesActive,
		plcPage.Policies,
		chsPage.Channels,
		thsPage.Things,
		user,
		thingActions,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "thingspolicies", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (us *uiService) AddThingsPolicy(token string, policy sdk.Policy) error {

	return us.sdk.CreateThingPolicy(policy, token)

}

func (us *uiService) DeleteThingsPolicy(token string, policy sdk.Policy) error {

	return us.sdk.DeleteThingPolicy(policy, token)

}

func (us *uiService) UpdateThingsPolicy(token string, policy sdk.Policy) error {

	return us.sdk.UpdateThingPolicy(policy, token)

}

func (us *uiService) ListGroupMembers(token, id string, page, limit uint64) ([]byte, error) {
	group, err := us.sdk.Group(id, token)
	if err != nil {
		return []byte{}, err
	}
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}

	members, err := us.sdk.Members(id, pgm, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := us.sdk.UserProfile(token)
	if err != nil {
		return []byte{}, err
	}

	users, err := us.sdk.Users(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	plcPage, err := us.sdk.ListUserPolicies(pgm, token)
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
		groupsActive,
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
	if err := us.tpls.ExecuteTemplate(&btpl, "groupconn", data); err != nil {
		return []byte{}, err
	}
	return btpl.Bytes(), nil
}

func (us *uiService) CreateGroups(token string, groups ...sdk.Group) error {
	for _, group := range groups {
		_, err := us.sdk.CreateGroup(group, token)
		if err != nil {
			return err
		}
	}
	return nil
}

func (us *uiService) ListGroups(token string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}
	grpPage, err := us.sdk.Groups(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := us.sdk.UserProfile(token)
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
		groupsActive,
		grpPage.Groups,
		user,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "groups", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (us *uiService) ViewGroup(token, id string) (b []byte, err error) {
	group, err := us.sdk.Group(id, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := us.sdk.UserProfile(token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		ID           string
		Group        sdk.Group
		User         sdk.User
	}{
		groupsActive,
		id,
		group,
		user,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "group", data); err != nil {
		return []byte{}, err
	}
	return btpl.Bytes(), nil
}

func (us *uiService) Assign(token, groupID, memberID string, memberType []string) error {

	return us.sdk.Assign(memberType, memberID, groupID, token)

}

func (us *uiService) Unassign(token, groupID, memberID string) error {

	return us.sdk.Unassign(memberID, groupID, token)

}

func (us *uiService) UpdateGroup(token, id string, group sdk.Group) error {
	_, err := us.sdk.UpdateGroup(group, token)

	return err
}

func (us *uiService) EnableGroup(token, id string) error {
	_, err := us.sdk.EnableGroup(id, token)

	return err
}

func (us *uiService) DisableGroup(token, id string) error {
	_, err := us.sdk.DisableGroup(id, token)

	return err
}

func (us *uiService) AddPolicy(token string, policy sdk.Policy) error {

	return us.sdk.CreateUserPolicy(policy, token)

}

func (us *uiService) ListPolicies(token string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}
	plcPage, err := us.sdk.ListUserPolicies(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	grpPage, err := us.sdk.Groups(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	users, err := us.sdk.Users(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := us.sdk.UserProfile(token)
	if err != nil {
		return []byte{}, err
	}

	noOfPages := int(math.Ceil(float64(plcPage.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		Policies     []sdk.Policy
		Groups       []sdk.Group
		Users        []sdk.User
		User         sdk.User
		Actions      []string
		CurrentPage  int
		Pages        int
		Limit        int
	}{
		usersPoliciesActive,
		plcPage.Policies,
		grpPage.Groups,
		users.Users,
		user,
		userActions,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "userspolicies", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (us *uiService) UpdatePolicy(token string, policy sdk.Policy) error {

	return us.sdk.UpdateUserPolicy(policy, token)

}

func (us *uiService) DeletePolicy(token string, policy sdk.Policy) error {

	return us.sdk.DeleteUserPolicy(policy, token)

}

func (us *uiService) Publish(token, thKey string, msg *messaging.Message) error {

	return us.sdk.SendMessage(msg.Channel, string(msg.Payload), thKey)

}

func (us *uiService) ReadMessage(_ string) ([]byte, error) {
	data := struct {
		NavbarActive string
	}{
		readMessagesActive,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "messagesread", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (us *uiService) WsConnection(_, chID, thKey string) ([]byte, error) {
	data := struct {
		NavbarActive string
		ChanID       string
		ThingKey     string
	}{
		readMessagesActive,
		chID,
		thKey,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "messagesread", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (us *uiService) GetRemoteTerminal(id, token string) ([]byte, error) {
	user, err := us.sdk.UserProfile(token)
	if err != nil {
		return []byte{}, err
	}

	data := struct {
		NavbarActive string
		ThingID      string
		User         sdk.User
	}{
		NavbarActive: bootstrapsActive,
		ThingID:      id,
		User:         user,
	}
	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "remoteTerminal", data); err != nil {
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

	user, err := us.sdk.UserProfile(token)
	if err != nil {
		return []byte{}, err
	}

	noOfPages := int(math.Ceil(float64(bootstraps.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		Bootstraps   []sdk.BootstrapConfig
		Things       []sdk.Thing
		User         sdk.User
		CurrentPage  int
		Pages        int
		Limit        int
	}{
		bootstrapsActive,
		bootstraps.Configs,
		things.Things,
		user,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "bootstraps", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}
func (us *uiService) ViewBootstrap(token, id string) ([]byte, error) {
	bootstrap, err := us.sdk.ViewBootstrap(id, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := us.sdk.UserProfile(token)
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
		User         sdk.User
	}{
		bootstrapsActive,
		bootstrap,
		user,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "bootstrap", data); err != nil {
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

func (us *uiService) GetEntities(token, item, name string, page, limit uint64) ([]byte, error) {
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
		groups, err := us.sdk.Groups(pgm, token)
		if err != nil {
			return []byte{}, err
		}
		items["data"] = groups.Groups
	case "users":
		users, err := us.sdk.Users(pgm, token)
		if err != nil {
			return []byte{}, err
		}
		items["data"] = users.Users
	case "things":
		things, err := us.sdk.Things(pgm, token)
		if err != nil {
			return []byte{}, err
		}
		items["data"] = things.Things
	case "channels":
		channels, err := us.sdk.Channels(pgm, token)
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
