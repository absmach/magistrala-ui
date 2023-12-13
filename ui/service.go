// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

// Package ui contains the domain concept definitions needed to support
// Magistrala ui adapter service functionality.
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

	"github.com/absmach/agent/pkg/bootstrap"
	"github.com/absmach/magistrala/pkg/errors"
	"github.com/absmach/magistrala/pkg/messaging"
	sdk "github.com/absmach/magistrala/pkg/sdk/go"
	"github.com/absmach/magistrala/pkg/transformers/senml"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	mfsenml "github.com/mainflux/senml"
	"golang.org/x/exp/slices"
)

const (
	templateDir        = "ui/web/template"
	enabled            = "enabled"
	statusAll          = "all"
	dashboardActive    = "dashboard"
	usersActive        = "users"
	thingsActive       = "things"
	groupsActive       = "groups"
	channelsActive     = "channels"
	readMessagesActive = "readmessages"
	bootstrapsActive   = "bootstraps"
	domainActive       = "domain"
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
	templates = []string{
		"header",
		"navbar",
		"tableheader",
		"tablefooter",
		"error",

		"bootstrap",
		"bootstraps",
		"terminal",

		"channel",
		"channelthings",
		"channels",
		"channelusers",
		"channelgroups",

		"group",
		"groupusers",
		"groups",
		"groupchannels",

		"index",

		"login",
		"resetpassword",
		"updatepassword",

		"messagesread",

		"thing",
		"thingchannels",
		"things",
		"thingusers",

		"users",
		"user",

		"domains",
		"domain",
		"member",
	}
	ErrToken                = errors.New("failed to create token")
	ErrTokenRefresh         = errors.New("failed to refresh token")
	ErrFailedCreate         = errors.New("failed to create entity")
	ErrFailedRetreive       = errors.New("failed to retrieve entity")
	ErrFailedUpdate         = errors.New("failed to update entity")
	ErrFailedEnable         = errors.New("failed to enable entity")
	ErrFailedDisable        = errors.New("failed to disable entity")
	ErrFailedAssign         = errors.New("failed to assign entity")
	ErrFailedUnassign       = errors.New("failed to unassign entity")
	ErrFailedConnect        = errors.New("failed to connect entity")
	ErrFailedDisconnect     = errors.New("failed to disconnect entity")
	ErrFailedCreatePolicy   = errors.New("failed to create policy")
	ErrFailedUpdatePolicy   = errors.New("failed to update policy")
	ErrFailedDeletePolicy   = errors.New("failed to delete policy")
	ErrExecTemplate         = errors.New("failed to execute template")
	ErrFailedReset          = errors.New("failed to reset password")
	ErrFailedUpdatePassword = errors.New("failed to update password")
	ErrFailedResetRequest   = errors.New("failed to send reset request email")
	ErrFailedPublish        = errors.New("failed to publish message")
	ErrFailedDelete         = errors.New("failed to delete entity")
	ErrFailedShare          = errors.New("failed to share entity")
	ErrFailedUnshare        = errors.New("failed to unshare entity")
	emptyData               = struct{}{}
	groupRelations          = []string{"administrator", "editor", "viewer", "member"}
	thingRelations          = []string{"administrator"}
)

// Service specifies service API.
type Service interface {
	// Index displays the landing page of the UI.
	Index(token, domainID string) ([]byte, error)
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
	Token(login sdk.Login) (sdk.Token, error)
	// RefreshToken retrieves a new access token and refresh token from the provided refresh token.
	RefreshToken(refreshToken string) (sdk.Token, error)
	// DomainLogin provides a user with an domain level access token and a refresh token.
	DomainLogin(login sdk.Login, refreshToken string) (sdk.Token, error)
	// UserProfile displays the user profile page.
	UserProfile(token string, page, limit uint64) ([]byte, error)

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

	// CreateThing creates a new thing.
	CreateThing(thing sdk.Thing, token string) error
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
	// EnableThing updates the status of the thing with the given ID to enabled.
	EnableThing(token, id string) error
	// DisableThing updates the status of the thing with the given ID to disabled.
	DisableThing(token, id string) error
	// ShareThing shares a thing with a user.
	ShareThing(token, thingID string, req sdk.UsersRelationRequest) error
	// UnshareThing unshares a thing with a user.
	UnshareThing(token, thingID string, req sdk.UsersRelationRequest) error
	// ListThingUsers retrieves users that share a thing.
	ListThingUsers(token, thingID, relation string, page, limit uint64) (b []byte, err error)
	// ListChannelsByThing retrieves a list of channels based on the given thing ID.
	ListChannelsByThing(token, thingID string, page, limit uint64) ([]byte, error)

	// CreateChannel creates a new channel.
	CreateChannel(channel sdk.Channel, token string) error
	// CreateChannels creates new channels.
	CreateChannels(token string, channels ...sdk.Channel) error
	// ListChannels retrieves channels owned/shared by a user.
	ListChannels(token string, page, limit uint64) ([]byte, error)
	// ViewChannel retrievs information about the channel with the given ID.
	ViewChannel(token, id string) ([]byte, error)
	// UpdateChannel updates the channel with the given ID.
	UpdateChannel(token, id string, channel sdk.Channel) error
	// ListThingsByChannel retrieves a list of things based on the given channel ID.
	ListThingsByChannel(token, channelID string, page, limit uint64) ([]byte, error)
	// EnableChannel updates the status of the channel with the given ID to enabled.
	EnableChannel(token, id string) error
	// DisableChannel updates the status of the channel with the given ID to disabled.
	DisableChannel(token, id string) error
	// Connect bulk connects things to channel(s) specified by ID.
	Connect(token string, connIDs sdk.Connection) error
	// Disconnect bulk disconnects thinfs to channel(s) specified by ID.
	Disconnect(token string, connIDs sdk.Connection) error
	// ConnectThing connects a thing to a channel specified by ID.
	ConnectThing(thingID, chanID, token string) error
	// DisconnectThing disconnects a thing from a channel specified by ID.
	DisconnectThing(thID, chID, token string) error
	// AddUserToChannel adds a user to a channel.
	AddUserToChannel(token, channelID string, req sdk.UsersRelationRequest) error
	// RemoveUserFromChannel removes a user from a channel.
	RemoveUserFromChannel(token, channelID string, req sdk.UsersRelationRequest) error
	// ListChannelUsers retrieves a list of users that are connected to a channel.
	ListChannelUsers(token, channelID, relation string, page, limit uint64) (b []byte, err error)
	// AddUserGroupToChannel adds a userGroup to a channel.
	AddUserGroupToChannel(token, channelID string, req sdk.UserGroupsRequest) error
	// RemoveGroupFromChannel removes a userGroup from a channel.
	RemoveUserGroupFromChannel(token, channelID string, req sdk.UserGroupsRequest) error
	// ListChannelUserGroups retrieves a list of userGroups connected to a channel.
	ListChannelUserGroups(token, channelID string, page, limit uint64) (b []byte, err error)

	// CreateGroups creates new groups.
	CreateGroups(token string, groups ...sdk.Group) error
	// ListGroupUsers retrieves the members of a group with a given ID.
	ListGroupUsers(token, id, relation string, page, limit uint64) ([]byte, error)
	// Assign adds a user to a group.
	Assign(token, groupID string, userRelation sdk.UsersRelationRequest) error
	// Unassign removes a user from a group.
	Unassign(token, groupID string, userRelation sdk.UsersRelationRequest) error
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
	// ListUserGroupChannels retrieves a list of channels that a userGroup is connected to.
	ListUserGroupChannels(token, groupID string, page, limit uint64) (b []byte, err error)

	// Publish facilitates a thing publishin messages to a channel.
	Publish(token, thKey string, msg *messaging.Message) error
	// ReadMessage facilitates a thing reading messages published in a channel.
	ReadMessage(token, chID, thKey string, page, limit uint64) ([]byte, error)
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

	// GetEntities retrieves all entities.
	GetEntities(token, item, name, domainID, permission string, page, limit uint64) ([]byte, error)
	// ErrorPage displays an error page.
	ErrorPage(errMsg string) ([]byte, error)

	// ListDomains retrieves domains owned/shared by a user.
	ListDomains(token string, page, limit uint64) ([]byte, error)
	// CreateDomain creates a new domain.
	CreateDomain(token string, domain sdk.Domain) error
	// UpdateDomain updates the domain with the given ID.
	UpdateDomain(token string, domain sdk.Domain) error
	// Domain displays the domain page.
	Domain(token, domainID, tabActive string, page, limit uint64) ([]byte, error)
	// AssignMember adds a member to an domain.
	AssignMember(token, domainID string, req sdk.UsersRelationRequest) error
	// UnassignMember removes a member from an domain.
	UnassignMember(token, domainID string, req sdk.UsersRelationRequest) error
	// View Member retrieves information about the domain Member with the given ID.
	ViewMember(token, userIdentity string) ([]byte, error)
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

func (us *uiService) Index(token, domainID string) (b []byte, err error) {
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

	users, err := us.sdk.ListDomainUsers(domainID, pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	things, err := us.sdk.Things(pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	groups, err := us.sdk.Groups(pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	channels, err := us.sdk.Channels(pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	enabledUsers, err := us.sdk.ListDomainUsers(domainID, enabledPgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	enabledThings, err := us.sdk.Things(enabledPgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	enabledGroups, err := us.sdk.Groups(enabledPgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	enabledChannels, err := us.sdk.Channels(enabledPgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	summary := dataSummary{
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

	data := struct {
		NavbarActive string
		Summary      dataSummary
	}{
		dashboardActive,
		summary,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "index", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) Login() ([]byte, error) {
	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "login", emptyData); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) Logout() error {
	return nil
}

func (us *uiService) PasswordResetRequest(email string) error {
	if err := us.sdk.ResetPasswordRequest(email); err != nil {
		return errors.Wrap(err, ErrFailedResetRequest)
	}

	return nil
}

func (us *uiService) PasswordReset(token, password, confirmPass string) error {
	if err := us.sdk.ResetPassword(token, password, confirmPass); err != nil {
		return errors.Wrap(err, ErrFailedReset)
	}

	return nil
}

func (us *uiService) ShowPasswordReset() ([]byte, error) {
	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "resetPassword", ""); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}
	return btpl.Bytes(), nil
}

func (us *uiService) PasswordUpdate(token string) ([]byte, error) {
	data := struct {
		NavbarActive string
	}{
		"password",
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "updatePassword", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) UpdatePassword(token, oldPass, newPass string) error {
	_, err := us.sdk.UpdatePassword(oldPass, newPass, token)
	if err != nil {
		return errors.Wrap(err, ErrFailedUpdatePassword)
	}
	return nil
}

func (us *uiService) Token(login sdk.Login) (sdk.Token, error) {
	token, err := us.sdk.CreateToken(login)
	if err != nil {
		return sdk.Token{}, errors.Wrap(err, ErrToken)
	}
	return token, nil
}

func (us *uiService) RefreshToken(refreshToken string) (sdk.Token, error) {
	token, err := us.sdk.RefreshToken(sdk.Login{}, refreshToken)
	if err != nil {
		return sdk.Token{}, errors.Wrap(err, ErrTokenRefresh)
	}

	return token, nil
}

func (us *uiService) DomainLogin(login sdk.Login, refreshToken string) (sdk.Token, error) {
	token, err := us.sdk.RefreshToken(login, refreshToken)
	if err != nil {
		return sdk.Token{}, err
	}

	return token, nil
}

func (us *uiService) UserProfile(token string, page, limit uint64) ([]byte, error) {
	user, err := us.sdk.UserProfile(token)
	if err != nil {
		return nil, err
	}

	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset: offset,
		Limit:  limit,
	}

	domainsPage, err := us.sdk.Domains(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	noOfPages := int(math.Ceil(float64(domainsPage.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		User         sdk.User
		Domains      []sdk.Domain
		CurrentPage  int
		Pages        int
		Limit        int
	}{
		"profile",
		user,
		domainsPage.Domains,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "profile", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (us *uiService) CreateUsers(token string, users ...sdk.User) error {
	for i := range users {
		_, err := us.sdk.CreateUser(users[i], token)
		if err != nil {
			return errors.Wrap(err, ErrFailedCreate)
		}
	}

	return nil
}

func (us *uiService) ListUsers(token string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset: offset,
		Limit:  limit,
	}
	users, err := us.sdk.Users(pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(users.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		Users        []sdk.User
		CurrentPage  int
		Pages        int
		Limit        int
	}{
		usersActive,
		users.Users,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "users", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) ViewUser(token, userID string) (b []byte, err error) {
	user, err := us.sdk.User(userID, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	data := struct {
		NavbarActive string
		User         sdk.User
	}{
		usersActive,
		user,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "user", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) UpdateUser(token, userID string, user sdk.User) error {
	if _, err := us.sdk.UpdateUser(user, token); err != nil {
		return errors.Wrap(err, ErrFailedUpdate)
	}

	return nil
}

func (us *uiService) UpdateUserTags(token, userID string, user sdk.User) error {
	if _, err := us.sdk.UpdateUserTags(user, token); err != nil {
		return errors.Wrap(err, ErrFailedUpdate)
	}

	return nil
}

func (us *uiService) UpdateUserIdentity(token, userID string, user sdk.User) error {
	if _, err := us.sdk.UpdateUserIdentity(user, token); err != nil {
		return errors.Wrap(err, ErrFailedUpdate)
	}

	return nil
}

func (us *uiService) UpdateUserOwner(token, userID string, user sdk.User) error {
	if _, err := us.sdk.UpdateUserIdentity(user, token); err != nil {
		return errors.Wrap(err, ErrFailedUpdate)
	}

	return nil
}

func (us *uiService) EnableUser(token, userID string) error {
	if _, err := us.sdk.EnableUser(userID, token); err != nil {
		return errors.Wrap(err, ErrFailedEnable)
	}

	return nil
}

func (us *uiService) DisableUser(token, userID string) error {
	if _, err := us.sdk.DisableUser(userID, token); err != nil {
		return errors.Wrap(err, ErrFailedDisable)
	}

	return nil
}

func (us *uiService) CreateThing(thing sdk.Thing, token string) error {
	_, err := us.sdk.CreateThing(thing, token)
	if err != nil {
		return errors.Wrap(err, ErrFailedCreate)
	}

	return nil
}

func (us *uiService) CreateThings(token string, things ...sdk.Thing) error {
	for _, thing := range things {
		_, err := us.sdk.CreateThing(thing, token)
		if err != nil {
			return errors.Wrap(err, ErrFailedCreate)
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
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(things.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		Things       []sdk.Thing
		CurrentPage  int
		Pages        int
		Limit        int
	}{
		thingsActive,
		things.Things,
		int(page),
		noOfPages,
		int(limit),
	}
	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "things", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}
	return btpl.Bytes(), nil
}

func (us *uiService) ViewThing(token, id string) (b []byte, err error) {
	thing, err := us.sdk.Thing(id, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	permissions, err := us.sdk.ThingPermissions(id, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	data := struct {
		NavbarActive string
		ID           string
		Thing        sdk.Thing
		Permissions  []string
	}{
		thingsActive,
		id,
		thing,
		permissions.Permissions,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "thing", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) UpdateThing(token, id string, thing sdk.Thing) error {
	if _, err := us.sdk.UpdateThing(thing, token); err != nil {
		return errors.Wrap(err, ErrFailedUpdate)
	}

	return nil
}

func (us *uiService) UpdateThingTags(token, id string, thing sdk.Thing) error {
	if _, err := us.sdk.UpdateThingTags(thing, token); err != nil {
		return errors.Wrap(err, ErrFailedUpdate)
	}

	return nil
}

func (us *uiService) UpdateThingSecret(token, id, secret string) error {
	if _, err := us.sdk.UpdateThingSecret(id, secret, token); err != nil {
		return errors.Wrap(err, ErrFailedUpdate)
	}

	return nil
}

func (us *uiService) EnableThing(token, id string) error {
	if _, err := us.sdk.EnableThing(id, token); err != nil {
		return errors.Wrap(err, ErrFailedEnable)
	}

	return nil
}

func (us *uiService) DisableThing(token, id string) error {
	if _, err := us.sdk.DisableThing(id, token); err != nil {
		return errors.Wrap(err, ErrFailedDisable)
	}

	return nil
}

func (us *uiService) ShareThing(token, thingID string, req sdk.UsersRelationRequest) error {
	if err := us.sdk.ShareThing(thingID, req, token); err != nil {
		return errors.Wrap(err, ErrFailedShare)
	}

	return nil
}

func (us *uiService) UnshareThing(token, thingID string, req sdk.UsersRelationRequest) error {
	if err := us.sdk.UnshareThing(thingID, req, token); err != nil {
		return errors.Wrap(err, ErrFailedUnshare)
	}

	return nil
}

func (us *uiService) ListThingUsers(token, thingID, relation string, page, limit uint64) (b []byte, err error) {
	offset := (page - 1) * limit
	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Permission: relation,
	}
	usersPage, err := us.sdk.ListThingUsers(thingID, pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	permissions, err := us.sdk.ThingPermissions(thingID, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(usersPage.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		ThingID      string
		Users        []sdk.User
		Relations    []string
		CurrentPage  int
		Pages        int
		Limit        int
		TabActive    string
		Permissions  []string
	}{
		thingsActive,
		thingID,
		usersPage.Users,
		thingRelations,
		int(page),
		noOfPages,
		int(limit),
		relation,
		permissions.Permissions,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "thingusers", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}
	return btpl.Bytes(), nil
}

func (us *uiService) ListChannelsByThing(token, thingID string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}

	chsPage, err := us.sdk.ChannelsByThing(thingID, pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	permissions, err := us.sdk.ThingPermissions(thingID, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(chsPage.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		ThingID      string
		Channels     []sdk.Channel
		CurrentPage  int
		Pages        int
		Limit        int
		Permissions  []string
	}{
		thingsActive,
		thingID,
		chsPage.Channels,
		int(page),
		noOfPages,
		int(limit),
		permissions.Permissions,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "thingchannels", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}
	return btpl.Bytes(), nil
}

func (us *uiService) CreateChannel(channel sdk.Channel, token string) error {
	_, err := us.sdk.CreateChannel(channel, token)
	if err != nil {
		return errors.Wrap(err, ErrFailedCreate)
	}

	return nil
}

func (us *uiService) CreateChannels(token string, channels ...sdk.Channel) error {
	for _, channel := range channels {
		_, err := us.sdk.CreateChannel(channel, token)
		if err != nil {
			return errors.Wrap(err, ErrFailedCreate)
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
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(chsPage.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		Channels     []sdk.Channel
		CurrentPage  int
		Pages        int
		Limit        int
	}{
		channelsActive,
		chsPage.Channels,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "channels", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) ViewChannel(token, id string) (b []byte, err error) {
	channel, err := us.sdk.Channel(id, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	permissions, err := us.sdk.ChannelPermissions(id, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	data := struct {
		NavbarActive string
		ID           string
		Channel      sdk.Channel
		Permissions  []string
	}{
		channelsActive,
		id,
		channel,
		permissions.Permissions,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "channel", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}
	return btpl.Bytes(), nil
}

func (us *uiService) UpdateChannel(token, id string, channel sdk.Channel) error {
	if _, err := us.sdk.UpdateChannel(channel, token); err != nil {
		return errors.Wrap(err, ErrFailedUpdate)
	}

	return nil
}

func (us *uiService) ListThingsByChannel(token, channelID string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}

	thsPage, err := us.sdk.ThingsByChannel(channelID, pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	permissions, err := us.sdk.ChannelPermissions(channelID, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(thsPage.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		ChannelID    string
		Things       []sdk.Thing
		CurrentPage  int
		Pages        int
		Limit        int
		Permissions  []string
	}{
		channelsActive,
		channelID,
		thsPage.Things,
		int(page),
		noOfPages,
		int(limit),
		permissions.Permissions,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "channelthings", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}
	return btpl.Bytes(), nil
}

func (us *uiService) EnableChannel(token, id string) error {
	_, err := us.sdk.EnableChannel(id, token)
	if err != nil {
		return errors.Wrap(err, ErrFailedEnable)
	}

	return nil
}

func (us *uiService) DisableChannel(token, id string) error {
	_, err := us.sdk.DisableChannel(id, token)
	if err != nil {
		return errors.Wrap(err, ErrFailedDisable)
	}

	return nil
}

func (us *uiService) Connect(token string, connIDs sdk.Connection) error {
	if err := us.sdk.Connect(connIDs, token); err != nil {
		return errors.Wrap(err, ErrFailedConnect)
	}

	return nil
}

func (us *uiService) Disconnect(token string, connIDs sdk.Connection) error {
	if err := us.sdk.Disconnect(connIDs, token); err != nil {
		return errors.Wrap(err, ErrFailedDisconnect)
	}

	return nil
}

func (us *uiService) ConnectThing(thingID, chanID, token string) error {
	if err := us.sdk.ConnectThing(thingID, chanID, token); err != nil {
		return errors.Wrap(err, ErrFailedConnect)
	}

	return nil
}

func (us *uiService) DisconnectThing(thID, chID, token string) error {
	if err := us.sdk.DisconnectThing(thID, chID, token); err != nil {
		return errors.Wrap(err, ErrFailedDisconnect)
	}

	return nil
}

func (gs *uiService) AddUserToChannel(token, channelID string, req sdk.UsersRelationRequest) error {
	if err := gs.sdk.AddUserToChannel(channelID, req, token); err != nil {
		return errors.Wrap(err, ErrFailedAssign)
	}

	return nil
}

func (gs *uiService) RemoveUserFromChannel(token, channelID string, req sdk.UsersRelationRequest) error {
	if err := gs.sdk.RemoveUserFromChannel(channelID, req, token); err != nil {
		return errors.Wrap(err, ErrFailedUnassign)
	}

	return nil
}

func (us *uiService) ListChannelUsers(token, channelID, relation string, page, limit uint64) (b []byte, err error) {
	offset := (page - 1) * limit
	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Permission: relation,
	}
	usersPage, err := us.sdk.ListChannelUsers(channelID, pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	permissions, err := us.sdk.ChannelPermissions(channelID, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(usersPage.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		ChannelID    string
		Users        []sdk.User
		Relations    []string
		CurrentPage  int
		Pages        int
		Limit        int
		TabActive    string
		Permissions  []string
	}{
		channelsActive,
		channelID,
		usersPage.Users,
		groupRelations,
		int(page),
		noOfPages,
		int(limit),
		relation,
		permissions.Permissions,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "channelusers", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) AddUserGroupToChannel(token, channelID string, req sdk.UserGroupsRequest) error {
	if err := gs.sdk.AddUserGroupToChannel(channelID, req, token); err != nil {
		return errors.Wrap(err, ErrFailedAssign)
	}

	return nil
}

func (gs *uiService) RemoveUserGroupFromChannel(token, channelID string, req sdk.UserGroupsRequest) error {
	if err := gs.sdk.RemoveUserGroupFromChannel(channelID, req, token); err != nil {
		return errors.Wrap(err, ErrFailedUnassign)
	}

	return nil
}

func (us *uiService) ListChannelUserGroups(token, channelID string, page, limit uint64) (b []byte, err error) {
	offset := (page - 1) * limit
	pgm := sdk.PageMetadata{
		Offset: offset,
		Limit:  limit,
	}
	groupsPage, err := us.sdk.ListChannelUserGroups(channelID, pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	permissions, err := us.sdk.ChannelPermissions(channelID, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(groupsPage.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		Groups       []sdk.Group
		ChannelID    string
		Relations    []string
		CurrentPage  int
		Pages        int
		Limit        int
		Permissions  []string
	}{
		channelsActive,
		groupsPage.Groups,
		channelID,
		groupRelations,
		int(page),
		noOfPages,
		int(limit),
		permissions.Permissions,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "channelgroups", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) CreateGroups(token string, groups ...sdk.Group) error {
	for _, group := range groups {
		_, err := us.sdk.CreateGroup(group, token)
		if err != nil {
			return errors.Wrap(err, ErrFailedCreate)
		}
	}

	return nil
}

func (us *uiService) ListGroupUsers(token, id, relation string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
		Permission: relation,
	}

	usersPage, err := us.sdk.ListGroupUsers(id, pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	permissions, err := us.sdk.GroupPermissions(id, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(usersPage.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		GroupID      string
		Users        []sdk.User
		Relations    []string
		CurrentPage  int
		Pages        int
		Limit        int
		TabActive    string
		Permissions  []string
	}{
		groupsActive,
		id,
		usersPage.Users,
		groupRelations,
		int(page),
		noOfPages,
		int(limit),
		relation,
		permissions.Permissions,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "groupusers", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}
	return btpl.Bytes(), nil
}

func (gs *uiService) Assign(token, groupID string, userRelation sdk.UsersRelationRequest) error {
	if err := gs.sdk.AddUserToGroup(groupID, userRelation, token); err != nil {
		return errors.Wrap(err, ErrFailedAssign)
	}

	return nil
}

func (gs *uiService) Unassign(token, groupID string, userRelation sdk.UsersRelationRequest) error {
	if err := gs.sdk.RemoveUserFromGroup(groupID, userRelation, token); err != nil {
		return errors.Wrap(err, ErrFailedUnassign)
	}

	return nil
}

func (us *uiService) ViewGroup(token, id string) (b []byte, err error) {
	group, err := us.sdk.Group(id, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	permissions, err := us.sdk.GroupPermissions(id, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	data := struct {
		NavbarActive string
		ID           string
		Group        sdk.Group
		Permissions  []string
	}{
		groupsActive,
		id,
		group,
		permissions.Permissions,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "group", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}
	return btpl.Bytes(), nil
}

func (us *uiService) UpdateGroup(token, id string, group sdk.Group) error {
	_, err := us.sdk.UpdateGroup(group, token)
	if err != nil {
		return errors.Wrap(err, ErrFailedUpdate)
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
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(grpPage.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		Groups       []sdk.Group
		CurrentPage  int
		Pages        int
		Limit        int
	}{
		groupsActive,
		grpPage.Groups,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "groups", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) EnableGroup(token, id string) error {
	if _, err := us.sdk.EnableGroup(id, token); err != nil {
		return errors.Wrap(err, ErrFailedEnable)
	}

	return nil
}

func (us *uiService) DisableGroup(token, id string) error {
	if _, err := us.sdk.DisableGroup(id, token); err != nil {
		return errors.Wrap(err, ErrFailedDisable)
	}

	return nil
}

func (us *uiService) ListUserGroupChannels(token, groupID string, page, limit uint64) (b []byte, err error) {
	offset := (page - 1) * limit
	pgm := sdk.PageMetadata{
		Offset: offset,
		Limit:  limit,
	}
	channelsPage, err := us.sdk.ListGroupChannels(groupID, pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	permissions, err := us.sdk.GroupPermissions(groupID, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(channelsPage.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		Channels     []sdk.Group
		GroupID      string
		Relations    []string
		CurrentPage  int
		Pages        int
		Limit        int
		Permissions  []string
	}{
		groupsActive,
		channelsPage.Groups,
		groupID,
		groupRelations,
		int(page),
		noOfPages,
		int(limit),
		permissions.Permissions,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "groupchannels", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (gs *uiService) Publish(token, thKey string, msg *messaging.Message) error {
	if err := gs.sdk.SendMessage(msg.Channel, string(msg.Payload), thKey); err != nil {
		return errors.Wrap(err, ErrFailedPublish)
	}

	return nil
}

func (us *uiService) ReadMessage(token, chID, thKey string, page, limit uint64) ([]byte, error) {
	var msg sdk.MessagesPage

	user, err := us.sdk.UserProfile(token)
	if err != nil {
		return []byte{}, err
	}

	if chID != "" {
		msg, err = us.sdk.ReadMessages(chID, thKey)
		if err != nil {
			return []byte{}, err
		}
	}

	noOfPages := int(math.Ceil(float64(msg.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		ChanID       string
		Msg          []senml.Message
		User         sdk.User
		CurrentPage  int
		Pages        int
		Limit        int
	}{
		readMessagesActive,
		chID,
		msg.Messages,
		user,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "messagesread", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) CreateBootstrap(token string, configs ...sdk.BootstrapConfig) error {
	for _, cfg := range configs {
		_, err := us.sdk.AddBootstrap(cfg, token)
		if err != nil {
			return errors.Wrap(err, ErrFailedCreate)
		}
	}
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
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	filter := sdk.PageMetadata{
		Offset: uint64(0),
		Total:  uint64(100),
		Limit:  uint64(100),
	}

	things, err := us.sdk.Things(filter, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
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
		bootstrapsActive,
		bootstraps.Configs,
		things.Things,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "bootstraps", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) UpdateBootstrap(token string, config sdk.BootstrapConfig) error {
	if err := us.sdk.UpdateBootstrap(config, token); err != nil {
		return errors.Wrap(err, ErrFailedUpdate)
	}

	return nil
}

func (us *uiService) UpdateBootstrapConnections(token string, config sdk.BootstrapConfig) error {
	channels, ok := config.Channels.([]string)
	if !ok {
		return errors.Wrap(errors.New("invalid channel"), ErrFailedUpdate)
	}
	return us.sdk.UpdateBootstrapConnection(config.ThingID, channels, token)
}

func (us *uiService) UpdateBootstrapCerts(token string, config sdk.BootstrapConfig) error {
	_, err := us.sdk.UpdateBootstrapCerts(config.ThingID, config.ClientCert, config.ClientKey, config.CACert, token)
	if err != nil {
		return errors.Wrap(err, ErrFailedUpdate)
	}

	return nil
}

func (us *uiService) DeleteBootstrap(token, id string) error {
	if err := us.sdk.RemoveBootstrap(id, token); err != nil {
		return errors.Wrap(err, ErrFailedDelete)
	}

	return nil
}

func (us *uiService) ViewBootstrap(token, id string) ([]byte, error) {
	bootstrap, err := us.sdk.ViewBootstrap(id, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
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
		return nil, errors.Wrap(errors.New("invalid channels"), ErrFailedRetreive)
	}

	data := struct {
		NavbarActive string
		Bootstrap    sdk.BootstrapConfig
	}{
		bootstrapsActive,
		bootstrap,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "bootstrap", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) GetRemoteTerminal(id, token string) ([]byte, error) {
	data := struct {
		NavbarActive string
		ThingID      string
	}{
		NavbarActive: bootstrapsActive,
		ThingID:      id,
	}
	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "remoteTerminal", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) ProcessTerminalCommand(ctx context.Context, id, tkn, command string, res chan string) error {
	cfg, err := us.sdk.ViewBootstrap(id, tkn)
	if err != nil {
		return errors.Wrap(err, ErrFailedRetreive)
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

	req := []mfsenml.Record{
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
		var data []mfsenml.Record
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

func (us *uiService) GetEntities(token, item, name, domainID, permission string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit
	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Name:       name,
		Permission: permission,
	}

	items := make(map[string]interface{})
	switch item {
	case "groups":
		groups, err := us.sdk.Groups(pgm, token)
		if err != nil {
			return []byte{}, errors.Wrap(err, ErrFailedRetreive)
		}
		items["data"] = groups.Groups
	case "users":
		users, err := us.sdk.Users(pgm, token)
		if err != nil {
			return []byte{}, errors.Wrap(err, ErrFailedRetreive)
		}
		items["data"] = users.Users
	case "things":
		things, err := us.sdk.Things(pgm, token)
		if err != nil {
			return []byte{}, errors.Wrap(err, ErrFailedRetreive)
		}
		items["data"] = things.Things
	case "channels":
		channels, err := us.sdk.Channels(pgm, token)
		if err != nil {
			return []byte{}, errors.Wrap(err, ErrFailedRetreive)
		}
		items["data"] = channels.Channels
	case "members":
		members, err := us.sdk.ListDomainUsers(domainID, pgm, token)
		if err != nil {
			return []byte{}, errors.Wrap(err, ErrFailedRetreive)
		}
		items["data"] = members.Users
	}

	jsonData, err := json.Marshal(items)
	if err != nil {
		return []byte{}, err
	}
	return jsonData, nil
}

func (us *uiService) ErrorPage(errMsg string) ([]byte, error) {
	data := struct {
		Error string
	}{
		errMsg,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "error", data); err != nil {
		return nil, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) ListDomains(token string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset: offset,
		Limit:  limit,
	}

	domainsPage, err := us.sdk.Domains(pgm, token)
	if err != nil {
		return []byte{}, err
	}

	user, err := us.sdk.UserProfile(token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(domainsPage.Total) / float64(limit)))

	data := struct {
		Domains     []sdk.Domain
		User        sdk.User
		CurrentPage int
		Pages       int
		Limit       int
	}{
		domainsPage.Domains,
		user,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "domains", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (us *uiService) CreateDomain(token string, domain sdk.Domain) error {
	_, err := us.sdk.CreateDomain(domain, token)
	return err
}

func (us *uiService) UpdateDomain(token string, domain sdk.Domain) error {
	_, err := us.sdk.UpdateDomain(domain, token)
	return err
}

func (us *uiService) Domain(token, domainID, tabActive string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset: offset,
		Limit:  limit,
	}
	domain, err := us.sdk.Domain(domainID, token)
	if err != nil {
		return []byte{}, err
	}

	membersPage, err := us.sdk.ListDomainUsers(domainID, pgm, token)
	if err != nil {
		return []byte{}, err
	}

	noOfPages := int(math.Ceil(float64(membersPage.Total) / float64(limit)))

	data := struct {
		NavbarActive string
		Domain       sdk.Domain
		Members      []sdk.User
		Relations    []string
		TabActive    string
		CurrentPage  int
		Pages        int
		Limit        int
	}{
		domainActive,
		domain,
		membersPage.Users,
		groupRelations,
		tabActive,
		int(page),
		noOfPages,
		int(limit),
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "domain", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (us *uiService) AssignMember(token, domainID string, req sdk.UsersRelationRequest) error {
	return us.sdk.AddUserToDomain(domainID, req, token)
}

func (us *uiService) UnassignMember(token, domainID string, req sdk.UsersRelationRequest) error {
	return us.sdk.RemoveUserFromDomain(domainID, req, token)
}

func (us *uiService) ViewMember(token, userIdentity string) (b []byte, err error) {
	pgm := sdk.PageMetadata{
		Identity: userIdentity,
	}
	usersPage, err := us.sdk.Users(pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}
	data := struct {
		NavbarActive string
		User         sdk.User
	}{
		domainActive,
		usersPage.Users[0],
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "member", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
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
		"unixTimeToHumanTime": func(t float64) string {
			if t == 0 {
				return ""
			}
			return time.Unix(int64(t), 0).String()
		},
		"hasPermission": func(permissions []string, permission string) bool {
			return slices.Contains(permissions, permission)
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
