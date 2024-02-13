// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

// Package ui contains the domain concept definitions needed to support
// Magistrala ui adapter service functionality.
package ui

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/absmach/agent/pkg/bootstrap"
	"github.com/absmach/magistrala"
	"github.com/absmach/magistrala/pkg/errors"
	sdk "github.com/absmach/magistrala/pkg/sdk/go"
	"github.com/absmach/magistrala/pkg/transformers/senml"
	mgsenml "github.com/absmach/senml"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"golang.org/x/exp/slices"
)

const (
	templatesDir            = "ui/web/templates"
	chartTemplatesDir       = "ui/web/templates/charts"
	enabled                 = "enabled"
	statePending            = "pending"
	statusAll               = "all"
	homepageActive          = "homepage"
	dashboardsActive        = "dashboards"
	dashboardActive         = "dashboard"
	usersActive             = "users"
	userActive              = "user"
	thingsActive            = "things"
	thingActive             = "thing"
	groupsActive            = "groups"
	groupActive             = "group"
	channelsActive          = "channels"
	channelActive           = "channel"
	readMessagesActive      = "readmessages"
	bootstrapsActive        = "bootstraps"
	domainActive            = "domain"
	domainsActive           = "domains"
	membersActive           = "members"
	invitationsActive       = "invitations"
	domainInvitationsActive = "domaininvitations"
	usersEndpoint           = "/users"
	thingsEndpoint          = "/things"
	channelsEndpoint        = "/channels"
	groupsEndpoint          = "/groups"
	bootstrapEndpoint       = "/bootstraps"
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

type breadcrumb struct {
	Name string
	URL  string
}

type Message struct {
	BaseTime float64 `json:"bt"`
	BaseUnit string  `json:"bu"`
	Name     string  `json:"n"`
	Unit     string  `json:"u"`
	Value    float64 `json:"v"`
}

type User struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Identity string `json:"identity"`
	Role     string `json:"role"`
}

type Domain struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

type SessionDetails struct {
	User        User   `json:"user"`
	Domain      Domain `json:"domain"`
	LoginStatus string `json:"login_status"`
}

var (
	templates = []string{
		"header",
		"navbar",
		"tableheader",
		"tablefooter",
		"error",
		"breadcrumb",
		"metadatamodal",
		"statusupdate",

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

		"registration",
		"login",
		"resetpassword",
		"updatepassword",

		"readmessages",

		"thing",
		"thingchannels",
		"things",
		"thingusers",

		"users",
		"user",

		"domains",
		"domain",
		"member",
		"members",
		"invitations",

		"dashboard",
		"dashboards",
	}

	chartTemplates = []string{
		"linechartmodal",
		"gaugemodal",
		"barchartmodal",
		"piechartmodal",
		"donutmodal",
		"speedgaugemodal",
		"tempgaugemodal",
		"stackedlinechartmodal",
		"arealinechartmodal",
		"horizontalbarchartmodal",
		"dynamicdatachartmodal",
		"doublebarchartmodal",
		"multiplelinechartmodal",
		"stepchartmodal",
		"multigaugemodal",
		"multibarchartmodal",
		"shareddatasetmodal",
		"valuecardmodal",
		"alarmcountmodal",
		"alarmstablemodal",
		"entitiestablemodal",
		"entitycountmodal",
		"progressbarmodal",
		"labelmodal",
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
	ErrConflict             = errors.New("entity already exists")
	ErrSessionType          = errors.New("invalid session type")

	ErrFailedViewDashboard     = errors.New("failed to view dashboard")
	ErrFailedDashboardSave     = errors.New("failed to save dashboard")
	ErrFailedRetrieveUserID    = errors.New("failed to retrieve user id")
	ErrFailedGenerateID        = errors.New("failed to generate id")
	ErrFailedDashboardRetrieve = errors.New("failed to retrieve dashboard")
	ErrFailedDashboardUpdate   = errors.New("failed to update dashboard")
	ErrFailedDashboardDelete   = errors.New("failed to delete dashboard")

	emptyData       = struct{}{}
	domainRelations = []string{"administrator", "editor", "viewer", "member"}
	groupRelations  = []string{"administrator", "editor", "viewer"}
	statusOptions   = []string{"all", "enabled", "disabled"}
)

// Service specifies service API.
type Service interface {
	// Index displays the landing page of the UI.
	Index(token string) ([]byte, error)
	// ViewRegistration displays the registration page.
	ViewRegistration() ([]byte, error)
	// RegisterUser registers a new user and logs them in.
	RegisterUser(user sdk.User) (sdk.Token, error)
	// KratosSignUp redirects the user to the kratos singup page.
	KratosSignUp() (string, error)
	// Login displays the login page.
	Login() ([]byte, error)
	// KratosSignIn redirects the user to the kratos login page.
	KratosSignIn() (string, error)
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
	// Token provides a user with an access token and a refresh token.
	Token(login sdk.Login) (sdk.Token, error)
	// RefreshToken retrieves a new access token and refresh token from the provided refresh token.
	RefreshToken(refreshToken string) (sdk.Token, error)
	// DomainLogin provides a user with an domain level access token and a refresh token.
	DomainLogin(login sdk.Login, refreshToken string) (sdk.Token, error)
	// Session retrieves the details of the user's session.
	Session(token, session, domainID string) (string, error)

	// CreateUsers creates new users.
	CreateUsers(token string, users ...sdk.User) error
	// ListUsers retrieves users owned/shared by a user.
	ListUsers(token, status string, page, limit uint64) ([]byte, error)
	// ViewUser retrieves information about the user with the given ID.
	ViewUser(token, id string) ([]byte, error)
	// UpdateUser updates the user with the given ID.
	UpdateUser(token string, user sdk.User) error
	// UpdateUserTags updates the tags of the user with the given ID.
	UpdateUserTags(token string, user sdk.User) error
	// UpdateUserIdentity updates the identity of the user with the given ID.
	UpdateUserIdentity(token string, user sdk.User) error
	// UpdateUserRole updates the roles of the user with the given ID.
	UpdateUserRole(token string, user sdk.User) error
	// EnableUser updates the status of a user with the given ID to enabled.
	EnableUser(token, id string) error
	// DisableUser updates the status of a user with the given ID to disabled.
	DisableUser(token, id string) error

	// CreateThing creates a new thing.
	CreateThing(thing sdk.Thing, token string) error
	// CreateThings creates new things.
	CreateThings(token string, things ...sdk.Thing) error
	// ListThings retrieves things owned/shared by a user.
	ListThings(token, status string, page, limit uint64) ([]byte, error)
	// ViewThing retrieves information about the thing with the given ID.
	ViewThing(token, id string) ([]byte, error)
	// UpdateThing updates the thing with the given ID.
	UpdateThing(token string, thing sdk.Thing) error
	// UpdateThingTags updates the tags of the thing with the given ID.
	UpdateThingTags(token string, thing sdk.Thing) error
	// UpdateThingSecret updates the secret of the thing with the given ID.
	UpdateThingSecret(token, id, secret string) error
	// EnableThing updates the status of the thing with the given ID to enabled.
	EnableThing(token, id string) error
	// DisableThing updates the status of the thing with the given ID to disabled.
	DisableThing(token, id string) error
	// ShareThing shares a thing with a user.
	ShareThing(token, id string, req sdk.UsersRelationRequest) error
	// UnshareThing unshares a thing with a user.
	UnshareThing(token, id string, req sdk.UsersRelationRequest) error
	// ListThingUsers retrieves users that share a thing.
	ListThingUsers(token, id, relation string, page, limit uint64) (b []byte, err error)
	// ListChannelsByThing retrieves a list of channels based on the given thing ID.
	ListChannelsByThing(token, id string, page, limit uint64) ([]byte, error)

	// CreateChannel creates a new channel.
	CreateChannel(channel sdk.Channel, token string) error
	// CreateChannels creates new channels.
	CreateChannels(token string, channels ...sdk.Channel) error
	// ListChannels retrieves channels owned/shared by a user.
	ListChannels(token, status string, page, limit uint64) ([]byte, error)
	// ViewChannel retrievs information about the channel with the given ID.
	ViewChannel(token, id string) ([]byte, error)
	// UpdateChannel updates the channel with the given ID.
	UpdateChannel(token string, channel sdk.Channel) error
	// ListThingsByChannel retrieves a list of things based on the given channel ID.
	ListThingsByChannel(token, id string, page, limit uint64) ([]byte, error)
	// EnableChannel updates the status of the channel with the given ID to enabled.
	EnableChannel(token, id string) error
	// DisableChannel updates the status of the channel with the given ID to disabled.
	DisableChannel(token, id string) error
	// Connect bulk connects things to channel(s) specified by ID.
	Connect(token string, connIDs sdk.Connection) error
	// Disconnect bulk disconnects thinfs to channel(s) specified by ID.
	Disconnect(token string, connIDs sdk.Connection) error
	// ConnectThing connects a thing to a channel specified by ID.
	ConnectThing(thingID, channelID, token string) error
	// DisconnectThing disconnects a thing from a channel specified by ID.
	DisconnectThing(thingID, channelID, token string) error
	// AddUserToChannel adds a user to a channel.
	AddUserToChannel(token, id string, req sdk.UsersRelationRequest) error
	// RemoveUserFromChannel removes a user from a channel.
	RemoveUserFromChannel(token, id string, req sdk.UsersRelationRequest) error
	// ListChannelUsers retrieves a list of users that are connected to a channel.
	ListChannelUsers(token, id, relation string, page, limit uint64) (b []byte, err error)
	// AddUserGroupToChannel adds a userGroup to a channel.
	AddUserGroupToChannel(token, id string, req sdk.UserGroupsRequest) error
	// RemoveGroupFromChannel removes a userGroup from a channel.
	RemoveUserGroupFromChannel(token, id string, req sdk.UserGroupsRequest) error
	// ListChannelUserGroups retrieves a list of userGroups connected to a channel.
	ListChannelUserGroups(token, id string, page, limit uint64) (b []byte, err error)

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
	UpdateGroup(token string, group sdk.Group) error
	// ListGroups retrieves the groups owned/shared by a user.
	ListGroups(token, status string, page, limit uint64) ([]byte, error)
	// EnableGroup updates the status of the group to enabled.
	EnableGroup(token, id string) error
	// DisableGroup updates the status of the group to disabled.
	DisableGroup(token, id string) error
	// ListUserGroupChannels retrieves a list of channels that a userGroup is connected to.
	ListUserGroupChannels(token, id string, page, limit uint64) (b []byte, err error)

	// Publish facilitates a thing publishin messages to a channel.
	Publish(channelID, thingKey string, message Message) error
	// ReadMessages retrieves messages published in a channel.
	ReadMessages(token, channelID, thingKey string, page, limit uint64) ([]byte, error)

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
	DeleteBootstrap(token, thingID string) error
	// UpdateBootstrapState updates bootstrap configuration state.
	UpdateBootstrapState(token string, config sdk.BootstrapConfig) error
	// ViewBootstrap retrieves a bootstrap config by thing id.
	ViewBootstrap(token, thingID string) ([]byte, error)
	// GetRemoteTerminal returns remote terminal for a bootstrap config with mainflux agent installed.
	GetRemoteTerminal(thingID string) ([]byte, error)
	// ProcessTerminalCommand sends mqtt command to agent and retrieves a response asynchronously.
	ProcessTerminalCommand(ctx context.Context, thingID, token, command string, res chan string) error

	// GetEntities retrieves all entities.
	GetEntities(token, entity, entityName, domainID, permission string, page, limit uint64) ([]byte, error)
	// ErrorPage displays an error page.
	ErrorPage(errMsg string) ([]byte, error)

	// ListDomains retrieves domains owned/shared by a user.
	ListDomains(token, status string, page, limit uint64) ([]byte, error)
	// CreateDomain creates a new domain.
	CreateDomain(token string, domain sdk.Domain) error
	// UpdateDomain updates the domain with the given ID.
	UpdateDomain(token string, domain sdk.Domain) error
	// Domain displays the domain page.
	Domain(token, id string) ([]byte, error)
	// EnableDomain updates the status of the domain to enabled.
	EnableDomain(token, id string) error
	// DisableDomain updates the status of the domain to disabled.
	DisableDomain(token, id string) error
	// AssignMember adds a member to a domain.
	AssignMember(token, domainID string, req sdk.UsersRelationRequest) error
	// UnassignMember removes a member from a domain.
	UnassignMember(token, domainID string, req sdk.UsersRelationRequest) error
	// View Member retrieves information about the domain Member with the given ID.
	ViewMember(token, userIdentity string) ([]byte, error)
	// Members retrieves the members of a domain with a given ID.
	Members(token, domainID string, page, limit uint64) ([]byte, error)

	// SendInvitation sends an invitation to a given user to join a domain.
	SendInvitation(token string, invitation sdk.Invitation) error
	// Invitations returns a list of invitations.
	Invitations(token, domainID string, page, limit uint64) ([]byte, error)
	// AcceptInvitation accepts an invitation by adding the user to the domain they were invited to.
	AcceptInvitation(token, domainID string) error
	// DeleteInvitation deletes an invitation.
	DeleteInvitation(token, userID, domainID string) error

	// Create a dashboard for a user.
	CreateDashboard(token string, dashboardReq DashboardReq) ([]byte, error)
	// View a dashboard for a user.
	ViewDashboard(token, dashboardID string) ([]byte, error)
	// List Dashboards retrieves all dashboards for a user.
	ListDashboards(token string, page, limit uint64) ([]byte, error)
	// Dashboards displays the dashboards page.
	Dashboards() ([]byte, error)
	// Update a dashboard for a user.
	UpdateDashboard(token, dashboardID string, dashboardReq DashboardReq) error
	// Delete a dashboard for a user.
	DeleteDashboard(token, dashboardID string) error
}

var _ Service = (*uiService)(nil)

type uiService struct {
	sdk          sdk.SDK
	tpls         *template.Template
	drepo        DashboardRepository
	idProvider   magistrala.IDProvider
	kratosConfig *KratosConfig
}

// New instantiates the HTTP adapter implementation.
func New(sdk sdk.SDK, db DashboardRepository, idp magistrala.IDProvider, cfg *KratosConfig) (Service, error) {
	tpl, err := parseTemplates(sdk, templates)
	if err != nil {
		return nil, err
	}
	return &uiService{
		sdk:          sdk,
		tpls:         tpl,
		drepo:        db,
		idProvider:   idp,
		kratosConfig: cfg,
	}, nil
}

func (us *uiService) Index(token string) (b []byte, err error) {
	pgm := sdk.PageMetadata{
		Offset: uint64(0),
		Status: statusAll,
	}

	enabledPgm := sdk.PageMetadata{
		Offset: uint64(0),
		Status: enabled,
	}

	users, err := us.sdk.Users(pgm, token)
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

	enabledUsers, err := us.sdk.Users(enabledPgm, token)
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
		NavbarActive   string
		CollapseActive string
		Summary        dataSummary
	}{
		homepageActive,
		homepageActive,
		summary,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "index", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) ViewRegistration() ([]byte, error) {
	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "registration", emptyData); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) RegisterUser(user sdk.User) (sdk.Token, error) {
	if _, err := us.sdk.CreateUser(user, ""); err != nil {
		return sdk.Token{}, errors.Wrap(err, ErrFailedCreate)
	}

	login := sdk.Login{
		Identity: user.Credentials.Identity,
		Secret:   user.Credentials.Secret,
	}
	return us.Token(login)
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

func (us *uiService) KratosSignIn() (string, error) {
	return us.kratosConfig.GenerateSignInURL()
}

func (us *uiService) KratosSignUp() (string, error) {
	return us.kratosConfig.GenerateSignUpURL()
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

func (us *uiService) PasswordUpdate() ([]byte, error) {
	data := struct {
		NavbarActive   string
		CollapseActive string
	}{
		"password",
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

func (us *uiService) Session(token, session, domainID string) (s string, err error) {
	user, err := us.sdk.UserProfile(token)
	if err != nil {
		return "", err
	}

	sessionDetails := SessionDetails{
		User: User{
			ID:       user.ID,
			Name:     user.Name,
			Identity: user.Credentials.Identity,
			Role:     user.Role,
		},
	}

	switch session {
	case "user":
		sessionDetails.LoginStatus = "user"
	case "domain":
		sessionDetails.LoginStatus = "domain"
		domain, err := us.sdk.Domain(domainID, token)
		if err != nil {
			return "", err
		}
		permissions, err := us.sdk.DomainPermissions(domainID, token)
		if err != nil {
			return "", err
		}
		sessionDetails.Domain.Name = domain.Name
		sessionDetails.Domain.ID = domain.ID
		sessionDetails.Domain.Permissions = permissions.Permissions
	default:
		return "", ErrSessionType
	}

	data, err := json.Marshal(sessionDetails)
	if err != nil {
		return "", err
	}

	encodedString := base64.StdEncoding.EncodeToString(data)

	return encodedString, nil
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

func (us *uiService) ListUsers(token, status string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset: offset,
		Limit:  limit,
		Status: status,
	}
	users, err := us.sdk.Users(pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(users.Total) / float64(limit)))

	crumbs := []breadcrumb{
		{Name: usersActive},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		Users          []sdk.User
		Breadcrumbs    []breadcrumb
		CurrentPage    int
		Pages          int
		Limit          int
		StatusOptions  []string
		Status         string
	}{
		usersActive,
		usersActive,
		users.Users,
		crumbs,
		int(page),
		noOfPages,
		int(limit),
		statusOptions,
		status,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "users", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) ViewUser(token, id string) (b []byte, err error) {
	user, err := us.sdk.User(id, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	crumbs := []breadcrumb{
		{Name: usersActive, URL: usersEndpoint},
		{Name: user.Name},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		Entity         sdk.User
		Breadcrumbs    []breadcrumb
		Path           string
	}{
		usersActive,
		userActive,
		user,
		crumbs,
		usersActive,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "user", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) UpdateUser(token string, user sdk.User) error {
	if _, err := us.sdk.UpdateUser(user, token); err != nil {
		return errors.Wrap(err, ErrFailedUpdate)
	}

	return nil
}

func (us *uiService) UpdateUserTags(token string, user sdk.User) error {
	if _, err := us.sdk.UpdateUserTags(user, token); err != nil {
		return errors.Wrap(err, ErrFailedUpdate)
	}

	return nil
}

func (us *uiService) UpdateUserIdentity(token string, user sdk.User) error {
	if _, err := us.sdk.UpdateUserIdentity(user, token); err != nil {
		return errors.Wrap(err, ErrFailedUpdate)
	}

	return nil
}

func (us *uiService) UpdateUserRole(token string, user sdk.User) error {
	if _, err := us.sdk.UpdateUserRole(user, token); err != nil {
		return errors.Wrap(err, ErrFailedUpdate)
	}

	return nil
}

func (us *uiService) EnableUser(token, id string) error {
	if _, err := us.sdk.EnableUser(id, token); err != nil {
		return errors.Wrap(err, ErrFailedEnable)
	}

	return nil
}

func (us *uiService) DisableUser(token, id string) error {
	if _, err := us.sdk.DisableUser(id, token); err != nil {
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

func (us *uiService) ListThings(token, status string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset: offset,
		Limit:  limit,
		Status: status,
	}
	things, err := us.sdk.Things(pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(things.Total) / float64(limit)))

	crumbs := []breadcrumb{
		{Name: thingsActive},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		Things         []sdk.Thing
		Breadcrumbs    []breadcrumb
		CurrentPage    int
		Pages          int
		Limit          int
		StatusOptions  []string
		Status         string
	}{
		thingsActive,
		thingsActive,
		things.Things,
		crumbs,
		int(page),
		noOfPages,
		int(limit),
		statusOptions,
		status,
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

	crumbs := []breadcrumb{
		{Name: thingsActive, URL: thingsEndpoint},
		{Name: thing.Name},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		ID             string
		Entity         sdk.Thing
		Permissions    []string
		Breadcrumbs    []breadcrumb
		Path           string
	}{
		thingsActive,
		thingActive,
		id,
		thing,
		permissions.Permissions,
		crumbs,
		thingsActive,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "thing", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) UpdateThing(token string, thing sdk.Thing) error {
	if _, err := us.sdk.UpdateThing(thing, token); err != nil {
		return errors.Wrap(err, ErrFailedUpdate)
	}

	return nil
}

func (us *uiService) UpdateThingTags(token string, thing sdk.Thing) error {
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

func (us *uiService) ShareThing(token, id string, req sdk.UsersRelationRequest) error {
	if err := us.sdk.ShareThing(id, req, token); err != nil {
		return errors.Wrap(err, ErrFailedShare)
	}

	return nil
}

func (us *uiService) UnshareThing(token, id string, req sdk.UsersRelationRequest) error {
	if err := us.sdk.UnshareThing(id, req, token); err != nil {
		return errors.Wrap(err, ErrFailedUnshare)
	}

	return nil
}

func (us *uiService) ListThingUsers(token, id, relation string, page, limit uint64) (b []byte, err error) {
	offset := (page - 1) * limit
	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Permission: relation,
	}
	usersPage, err := us.sdk.ListThingUsers(id, pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	permissions, err := us.sdk.ThingPermissions(id, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(usersPage.Total) / float64(limit)))

	crumbs := []breadcrumb{
		{Name: thingsActive, URL: thingsEndpoint},
		{Name: id, URL: thingsEndpoint + "/" + id},
		{Name: "Share"},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		ThingID        string
		Users          []sdk.User
		CurrentPage    int
		Pages          int
		Limit          int
		TabActive      string
		Permissions    []string
		Breadcrumbs    []breadcrumb
	}{
		thingsActive,
		thingsActive,
		id,
		usersPage.Users,
		int(page),
		noOfPages,
		int(limit),
		relation,
		permissions.Permissions,
		crumbs,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "thingusers", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}
	return btpl.Bytes(), nil
}

func (us *uiService) ListChannelsByThing(token, id string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Visibility: statusAll,
	}

	chsPage, err := us.sdk.ChannelsByThing(id, pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	permissions, err := us.sdk.ThingPermissions(id, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	thing, err := us.sdk.Thing(id, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(chsPage.Total) / float64(limit)))

	crumbs := []breadcrumb{
		{Name: thingsActive, URL: thingsEndpoint},
		{Name: id, URL: thingsEndpoint + "/" + id},
		{Name: "Connect"},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		Thing          sdk.Thing
		Channels       []sdk.Channel
		CurrentPage    int
		Pages          int
		Limit          int
		Permissions    []string
		Breadcrumbs    []breadcrumb
	}{
		thingsActive,
		thingsActive,
		thing,
		chsPage.Channels,
		int(page),
		noOfPages,
		int(limit),
		permissions.Permissions,
		crumbs,
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

func (us *uiService) ListChannels(token, status string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset: offset,
		Limit:  limit,
		Status: status,
	}
	chsPage, err := us.sdk.Channels(pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(chsPage.Total) / float64(limit)))

	crumbs := []breadcrumb{
		{Name: channelsActive},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		Channels       []sdk.Channel
		CurrentPage    int
		Pages          int
		Limit          int
		Breadcrumbs    []breadcrumb
		StatusOptions  []string
		Status         string
	}{
		channelsActive,
		channelsActive,
		chsPage.Channels,
		int(page),
		noOfPages,
		int(limit),
		crumbs,
		statusOptions,
		status,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "channels", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) ViewChannel(token, channelID string) (b []byte, err error) {
	channel, err := us.sdk.Channel(channelID, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	permissions, err := us.sdk.ChannelPermissions(channelID, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	crumbs := []breadcrumb{
		{Name: channelsActive, URL: channelsEndpoint},
		{Name: channel.Name},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		ID             string
		Entity         sdk.Channel
		Permissions    []string
		Breadcrumbs    []breadcrumb
		Path           string
	}{
		channelsActive,
		channelActive,
		channelID,
		channel,
		permissions.Permissions,
		crumbs,
		channelsActive,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "channel", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}
	return btpl.Bytes(), nil
}

func (us *uiService) UpdateChannel(token string, channel sdk.Channel) error {
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

	crumbs := []breadcrumb{
		{Name: channelsActive, URL: channelsEndpoint},
		{Name: channelID, URL: channelsEndpoint + "/" + channelID},
		{Name: "Connect"},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		ChannelID      string
		Things         []sdk.Thing
		CurrentPage    int
		Pages          int
		Limit          int
		Permissions    []string
		Breadcrumbs    []breadcrumb
	}{
		channelsActive,
		channelsActive,
		channelID,
		thsPage.Things,
		int(page),
		noOfPages,
		int(limit),
		permissions.Permissions,
		crumbs,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "channelthings", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}
	return btpl.Bytes(), nil
}

func (us *uiService) EnableChannel(token, channelID string) error {
	_, err := us.sdk.EnableChannel(channelID, token)
	if err != nil {
		return errors.Wrap(err, ErrFailedEnable)
	}

	return nil
}

func (us *uiService) DisableChannel(token, channelID string) error {
	_, err := us.sdk.DisableChannel(channelID, token)
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

func (us *uiService) ConnectThing(thingID, channelID, token string) error {
	if err := us.sdk.ConnectThing(thingID, channelID, token); err != nil {
		return errors.Wrap(err, ErrFailedConnect)
	}

	return nil
}

func (us *uiService) DisconnectThing(thingID, channelID, token string) error {
	if err := us.sdk.DisconnectThing(thingID, channelID, token); err != nil {
		return errors.Wrap(err, ErrFailedDisconnect)
	}

	return nil
}

func (us *uiService) AddUserToChannel(token, id string, req sdk.UsersRelationRequest) error {
	if err := us.sdk.AddUserToChannel(id, req, token); err != nil {
		return errors.Wrap(err, ErrFailedAssign)
	}

	return nil
}

func (us *uiService) RemoveUserFromChannel(token, id string, req sdk.UsersRelationRequest) error {
	if err := us.sdk.RemoveUserFromChannel(id, req, token); err != nil {
		return errors.Wrap(err, ErrFailedUnassign)
	}

	return nil
}

func (us *uiService) ListChannelUsers(token, id, relation string, page, limit uint64) (b []byte, err error) {
	offset := (page - 1) * limit
	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Permission: relation,
	}
	usersPage, err := us.sdk.ListChannelUsers(id, pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	permissions, err := us.sdk.ChannelPermissions(id, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(usersPage.Total) / float64(limit)))

	crumbs := []breadcrumb{
		{Name: channelsActive, URL: channelsEndpoint},
		{Name: id, URL: channelsEndpoint + "/" + id},
		{Name: "Assign Users"},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		ChannelID      string
		Users          []sdk.User
		Relations      []string
		CurrentPage    int
		Pages          int
		Limit          int
		TabActive      string
		Permissions    []string
		Breadcrumbs    []breadcrumb
	}{
		channelsActive,
		channelsActive,
		id,
		usersPage.Users,
		groupRelations,
		int(page),
		noOfPages,
		int(limit),
		relation,
		permissions.Permissions,
		crumbs,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "channelusers", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}
	return btpl.Bytes(), nil
}

func (us *uiService) AddUserGroupToChannel(token, id string, req sdk.UserGroupsRequest) error {
	if err := us.sdk.AddUserGroupToChannel(id, req, token); err != nil {
		return errors.Wrap(err, ErrFailedAssign)
	}

	return nil
}

func (us *uiService) RemoveUserGroupFromChannel(token, id string, req sdk.UserGroupsRequest) error {
	if err := us.sdk.RemoveUserGroupFromChannel(id, req, token); err != nil {
		return errors.Wrap(err, ErrFailedUnassign)
	}

	return nil
}

func (us *uiService) ListChannelUserGroups(token, id string, page, limit uint64) (b []byte, err error) {
	offset := (page - 1) * limit
	pgm := sdk.PageMetadata{
		Offset: offset,
		Limit:  limit,
	}
	groupsPage, err := us.sdk.ListChannelUserGroups(id, pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	permissions, err := us.sdk.ChannelPermissions(id, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(groupsPage.Total) / float64(limit)))

	crumbs := []breadcrumb{
		{Name: channelsActive, URL: channelsEndpoint},
		{Name: id, URL: channelsEndpoint + "/" + id},
		{Name: "Assign Groups"},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		Groups         []sdk.Group
		ChannelID      string
		Relations      []string
		CurrentPage    int
		Pages          int
		Limit          int
		Permissions    []string
		Breadcrumbs    []breadcrumb
	}{
		channelsActive,
		channelsActive,
		groupsPage.Groups,
		id,
		groupRelations,
		int(page),
		noOfPages,
		int(limit),
		permissions.Permissions,
		crumbs,
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

	crumbs := []breadcrumb{
		{Name: groupsActive, URL: groupsEndpoint},
		{Name: id, URL: groupsEndpoint + "/" + id},
		{Name: "Assign Users"},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		GroupID        string
		Users          []sdk.User
		Relations      []string
		CurrentPage    int
		Pages          int
		Limit          int
		TabActive      string
		Permissions    []string
		Breadcrumbs    []breadcrumb
	}{
		groupsActive,
		groupsActive,
		id,
		usersPage.Users,
		groupRelations,
		int(page),
		noOfPages,
		int(limit),
		relation,
		permissions.Permissions,
		crumbs,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "groupusers", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}
	return btpl.Bytes(), nil
}

func (us *uiService) Assign(token, groupID string, userRelation sdk.UsersRelationRequest) error {
	if err := us.sdk.AddUserToGroup(groupID, userRelation, token); err != nil {
		return errors.Wrap(err, ErrFailedAssign)
	}

	return nil
}

func (us *uiService) Unassign(token, groupID string, userRelation sdk.UsersRelationRequest) error {
	if err := us.sdk.RemoveUserFromGroup(groupID, userRelation, token); err != nil {
		return errors.Wrap(err, ErrFailedUnassign)
	}

	return nil
}

func (us *uiService) ViewGroup(token, id string) (b []byte, err error) {
	group, err := us.sdk.Group(id, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	parent, err := us.sdk.Group(group.ParentID, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	permissions, err := us.sdk.GroupPermissions(id, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	crumbs := []breadcrumb{
		{Name: groupsActive, URL: groupsEndpoint},
		{Name: group.Name},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		Entity         sdk.Group
		Parent         string
		Permissions    []string
		Breadcrumbs    []breadcrumb
		Path           string
	}{
		groupsActive,
		groupActive,
		group,
		parent.Name,
		permissions.Permissions,
		crumbs,
		groupsActive,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "group", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}
	return btpl.Bytes(), nil
}

func (us *uiService) UpdateGroup(token string, group sdk.Group) error {
	_, err := us.sdk.UpdateGroup(group, token)
	if err != nil {
		return errors.Wrap(err, ErrFailedUpdate)
	}

	return nil
}

func (us *uiService) ListGroups(token, status string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset: offset,
		Limit:  limit,
		Status: status,
	}
	grpPage, err := us.sdk.Groups(pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(grpPage.Total) / float64(limit)))

	crumbs := []breadcrumb{
		{Name: groupsActive},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		Groups         []sdk.Group
		CurrentPage    int
		Pages          int
		Limit          int
		Breadcrumbs    []breadcrumb
		StatusOptions  []string
		Status         string
	}{
		groupsActive,
		groupsActive,
		grpPage.Groups,
		int(page),
		noOfPages,
		int(limit),
		crumbs,
		statusOptions,
		status,
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

func (us *uiService) ListUserGroupChannels(token, id string, page, limit uint64) (b []byte, err error) {
	offset := (page - 1) * limit
	pgm := sdk.PageMetadata{
		Offset: offset,
		Limit:  limit,
	}
	channelsPage, err := us.sdk.ListGroupChannels(id, pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	permissions, err := us.sdk.GroupPermissions(id, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(channelsPage.Total) / float64(limit)))

	crumbs := []breadcrumb{
		{Name: groupsActive, URL: groupsEndpoint},
		{Name: id, URL: groupsEndpoint + "/" + id},
		{Name: "Assign Channels"},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		Channels       []sdk.Group
		GroupID        string
		Relations      []string
		CurrentPage    int
		Pages          int
		Limit          int
		Permissions    []string
		Breadcrumbs    []breadcrumb
	}{
		groupsActive,
		groupsActive,
		channelsPage.Groups,
		id,
		groupRelations,
		int(page),
		noOfPages,
		int(limit),
		permissions.Permissions,
		crumbs,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "groupchannels", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) ReadMessages(token, channelID, thingKey string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit
	pgm := sdk.PageMetadata{
		Offset: offset,
		Limit:  limit,
	}
	msg, err := us.sdk.ReadMessages(pgm, channelID, token)
	if err != nil {
		return []byte{}, err
	}

	noOfPages := int(math.Ceil(float64(msg.Total) / float64(limit)))

	crumbs := []breadcrumb{
		{Name: "Read Messages"},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		ChID           string
		ThKey          string
		Msg            []senml.Message
		CurrentPage    int
		Pages          int
		Limit          int
		Breadcrumbs    []breadcrumb
	}{
		thingsActive,
		readMessagesActive,
		channelID,
		thingKey,
		msg.Messages,
		int(page),
		noOfPages,
		int(limit),
		crumbs,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "readmessages", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) Publish(channelID, thingKey string, message Message) error {
	jsonMessage, err := json.Marshal(message)
	if err != nil {
		return errors.Wrap(err, ErrFailedPublish)
	}

	messageArray := "[" + string(jsonMessage) + "]"

	if err := us.sdk.SendMessage(channelID, messageArray, thingKey); err != nil {
		return errors.Wrap(err, ErrFailedPublish)
	}

	return nil
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

	crumbs := []breadcrumb{
		{Name: bootstrapsActive},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		Bootstraps     []sdk.BootstrapConfig
		Things         []sdk.Thing
		CurrentPage    int
		Pages          int
		Limit          int
		Breadcrumbs    []breadcrumb
	}{
		bootstrapsActive,
		bootstrapsActive,
		bootstraps.Configs,
		things.Things,
		int(page),
		noOfPages,
		int(limit),
		crumbs,
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

func (us *uiService) DeleteBootstrap(token, thingID string) error {
	if err := us.sdk.RemoveBootstrap(thingID, token); err != nil {
		return errors.Wrap(err, ErrFailedDelete)
	}

	return nil
}

func (us *uiService) UpdateBootstrapState(token string, config sdk.BootstrapConfig) error {
	if err := us.sdk.Whitelist(config, token); err != nil {
		return errors.Wrap(err, ErrFailedUpdate)
	}

	return nil
}

func (us *uiService) ViewBootstrap(token, thingID string) ([]byte, error) {
	bootstrap, err := us.sdk.ViewBootstrap(thingID, token)
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

	thing, err := us.sdk.Thing(thingID, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	crumbs := []breadcrumb{
		{Name: bootstrapsActive, URL: bootstrapEndpoint},
		{Name: thingID},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		Bootstrap      sdk.BootstrapConfig
		Thing          sdk.Thing
		Breadcrumbs    []breadcrumb
	}{
		bootstrapsActive,
		bootstrapsActive,
		bootstrap,
		thing,
		crumbs,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "bootstrap", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) GetRemoteTerminal(thingID string) ([]byte, error) {
	crumbs := []breadcrumb{
		{Name: bootstrapsActive, URL: bootstrapEndpoint},
		{Name: thingID, URL: bootstrapEndpoint + "/" + thingID},
		{Name: "Remote Terminal"},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		ThingID        string
		Breadcrumbs    []breadcrumb
	}{
		bootstrapsActive,
		bootstrapsActive,
		thingID,
		crumbs,
	}
	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "remoteTerminal", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) ProcessTerminalCommand(ctx context.Context, thingID, tkn, command string, res chan string) error {
	cfg, err := us.sdk.ViewBootstrap(thingID, tkn)
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

	req := []mgsenml.Record{
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
		var data []mgsenml.Record
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

func (us *uiService) GetEntities(token, entity, entityName, domainID, permission string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit
	pgm := sdk.PageMetadata{
		Offset:     offset,
		Limit:      limit,
		Name:       entityName,
		Permission: permission,
	}

	items := make(map[string]interface{})
	switch entity {
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
	case "domains":
		domains, err := us.sdk.Domains(pgm, token)
		if err != nil {
			return []byte{}, errors.Wrap(err, ErrFailedRetreive)
		}
		items["data"] = domains.Domains
	}

	data, err := json.Marshal(items)
	if err != nil {
		return []byte{}, err
	}
	return data, nil
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

func (us *uiService) ListDomains(token, status string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset: offset,
		Limit:  limit,
		Status: status,
	}

	domainsPage, err := us.sdk.Domains(pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(ErrFailedRetreive, err)
	}

	noOfPages := int(math.Ceil(float64(domainsPage.Total) / float64(limit)))

	crumbs := []breadcrumb{
		{Name: domainsActive},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		Domains        []sdk.Domain
		CurrentPage    int
		Pages          int
		Limit          int
		Breadcrumbs    []breadcrumb
		StatusOptions  []string
		Status         string
	}{
		domainsActive,
		domainsActive,
		domainsPage.Domains,
		int(page),
		noOfPages,
		int(limit),
		crumbs,
		statusOptions,
		status,
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

func (us *uiService) Domain(token, id string) ([]byte, error) {
	domain, err := us.sdk.Domain(id, token)
	if err != nil {
		return []byte{}, errors.Wrap(ErrFailedRetreive, err)
	}

	permissions, err := us.sdk.DomainPermissions(id, token)
	if err != nil {
		return []byte{}, errors.Wrap(ErrFailedRetreive, err)
	}

	crumbs := []breadcrumb{
		{Name: domain.Name},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		Entity         sdk.Domain
		Breadcrumbs    []breadcrumb
		Permissions    []string
		Path           string
	}{
		domainActive,
		domainActive,
		domain,
		crumbs,
		permissions.Permissions,
		domainsActive,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "domain", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (us *uiService) EnableDomain(token, id string) error {
	if err := us.sdk.EnableDomain(id, token); err != nil {
		return errors.Wrap(err, ErrFailedEnable)
	}

	return nil
}

func (us *uiService) DisableDomain(token, id string) error {
	if err := us.sdk.DisableDomain(id, token); err != nil {
		return errors.Wrap(err, ErrFailedDisable)
	}

	return nil
}

func (us *uiService) AssignMember(token, domainID string, req sdk.UsersRelationRequest) error {
	if err := us.sdk.AddUserToDomain(domainID, req, token); err != nil {
		return errors.Wrap(ErrFailedAssign, err)
	}

	return nil
}

func (us *uiService) UnassignMember(token, domainID string, req sdk.UsersRelationRequest) error {
	if err := us.sdk.RemoveUserFromDomain(domainID, req, token); err != nil {
		return errors.Wrap(ErrFailedUnassign, err)
	}

	return nil
}

func (us *uiService) ViewMember(token, userIdentity string) (b []byte, err error) {
	pgm := sdk.PageMetadata{
		Identity: userIdentity,
	}
	usersPage, err := us.sdk.Users(pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	crumbs := []breadcrumb{
		{Name: membersActive, URL: "/members"},
		{Name: usersPage.Users[0].Name},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		User           sdk.User
		Breadcrumbs    []breadcrumb
	}{
		membersActive,
		domainActive,
		usersPage.Users[0],
		crumbs,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "member", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) Members(token, domainID string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset: offset,
		Limit:  limit,
	}

	membersPage, err := us.sdk.ListDomainUsers(domainID, pgm, token)
	if err != nil {
		return []byte{}, err
	}

	noOfPages := int(math.Ceil(float64(membersPage.Total) / float64(limit)))

	crumbs := []breadcrumb{
		{Name: membersActive},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		DomainID       string
		Members        []sdk.User
		Relations      []string
		CurrentPage    int
		Pages          int
		Limit          int
		Breadcrumbs    []breadcrumb
	}{
		membersActive,
		domainActive,
		domainID,
		membersPage.Users,
		domainRelations,
		int(page),
		noOfPages,
		int(limit),
		crumbs,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "members", data); err != nil {
		return []byte{}, err
	}

	return btpl.Bytes(), nil
}

func (us *uiService) SendInvitation(token string, invitation sdk.Invitation) error {
	return us.sdk.SendInvitation(invitation, token)
}

func (us *uiService) Invitations(token, domainID string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit

	pgm := sdk.PageMetadata{
		Offset:   offset,
		Limit:    limit,
		DomainID: domainID,
		State:    statePending,
	}
	invitationsPage, err := us.sdk.Invitations(pgm, token)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(invitationsPage.Total) / float64(limit)))

	var crumbs []breadcrumb
	var collapseActive, navbarActive string

	switch domainID {
	case "":
		crumbs = []breadcrumb{
			{Name: invitationsActive},
		}
		collapseActive = domainsActive
		navbarActive = invitationsActive

	default:
		crumbs = []breadcrumb{
			{Name: "Domain-Invitations"},
		}
		collapseActive = domainActive
		navbarActive = domainInvitationsActive
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		DomainID       string
		Invitations    []sdk.Invitation
		Relations      []string
		CurrentPage    int
		Pages          int
		Limit          int
		Breadcrumbs    []breadcrumb
	}{
		navbarActive,
		collapseActive,
		domainID,
		invitationsPage.Invitations,
		domainRelations,
		int(page),
		noOfPages,
		int(limit),
		crumbs,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "invitations", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) AcceptInvitation(token, domainID string) error {
	return us.sdk.AcceptInvitation(domainID, token)
}

func (us *uiService) DeleteInvitation(token, userID, domainID string) error {
	return us.sdk.DeleteInvitation(userID, domainID, token)
}

func (us *uiService) CreateDashboard(token string, dashboardReq DashboardReq) ([]byte, error) {
	user, sdkerr := us.sdk.UserProfile(token)
	if sdkerr != nil {
		return []byte{}, errors.Wrap(ErrFailedRetrieveUserID, sdkerr)
	}

	dashboardID, err := us.idProvider.ID()
	if err != nil {
		return []byte{}, errors.Wrap(ErrFailedGenerateID, err)
	}
	dashboard := Dashboard{
		ID:          dashboardID,
		CreatedBy:   user.ID,
		Name:        dashboardReq.Name,
		Description: dashboardReq.Description,
		Layout:      dashboardReq.Layout,
		CreatedAt:   time.Now(),
	}

	ds, err := us.drepo.Create(context.Background(), dashboard)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedDashboardSave)
	}

	item := make(map[string]interface{})
	item["dashboard"] = ds
	data, err := json.Marshal(item)
	if err != nil {
		return []byte{}, err
	}

	return data, nil
}

func (us *uiService) ViewDashboard(token, dashboardID string) ([]byte, error) {
	var btpl bytes.Buffer
	charts := CreateItem()

	user, sdkerr := us.sdk.UserProfile(token)
	if sdkerr != nil {
		return btpl.Bytes(), errors.Wrap(ErrFailedRetrieveUserID, sdkerr)
	}

	dashboard, err := us.drepo.Retrieve(context.Background(), dashboardID, user.ID)
	if err != nil {
		return btpl.Bytes(), errors.Wrap(ErrFailedDashboardRetrieve, err)
	}

	crumbs := []breadcrumb{
		{Name: dashboardsActive, URL: "/dashboards"},
		{Name: dashboard.Name},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		Charts         []Item
		Dashboard      Dashboard
		Breadcrumbs    []breadcrumb
	}{
		dashboardsActive,
		dashboardsActive,
		charts,
		dashboard,
		crumbs,
	}

	if err := us.tpls.ExecuteTemplate(&btpl, "dashboard", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) ListDashboards(token string, page, limit uint64) ([]byte, error) {
	offset := (page - 1) * limit

	user, sdkerr := us.sdk.UserProfile(token)
	if sdkerr != nil {
		return []byte{}, errors.Wrap(ErrFailedRetrieveUserID, sdkerr)
	}

	pgm := DashboardPageMeta{
		Offset:    offset,
		Limit:     limit,
		CreatedBy: user.ID,
	}
	dashboardsPage, err := us.drepo.RetrieveAll(context.Background(), pgm)
	if err != nil {
		return []byte{}, errors.Wrap(err, ErrFailedRetreive)
	}

	noOfPages := int(math.Ceil(float64(dashboardsPage.Total) / float64(limit)))

	items := make(map[string]interface{})
	items["dashboards"] = dashboardsPage.Dashboards
	items["total"] = dashboardsPage.Total
	items["limit"] = limit
	items["current_page"] = page
	items["pages"] = noOfPages
	data, err := json.Marshal(items)
	if err != nil {
		return []byte{}, err
	}

	return data, nil
}

func (us *uiService) Dashboards() ([]byte, error) {
	crumbs := []breadcrumb{
		{Name: dashboardsActive},
	}

	data := struct {
		NavbarActive   string
		CollapseActive string
		Breadcrumbs    []breadcrumb
	}{
		dashboardsActive,
		dashboardsActive,
		crumbs,
	}

	var btpl bytes.Buffer
	if err := us.tpls.ExecuteTemplate(&btpl, "dashboards", data); err != nil {
		return []byte{}, errors.Wrap(err, ErrExecTemplate)
	}

	return btpl.Bytes(), nil
}

func (us *uiService) UpdateDashboard(token, dashboardID string, dashboardReq DashboardReq) error {
	user, sdkerr := us.sdk.UserProfile(token)
	if sdkerr != nil {
		return errors.Wrap(ErrFailedRetrieveUserID, sdkerr)
	}

	if err := us.drepo.Update(context.Background(), dashboardID, user.ID, dashboardReq); err != nil {
		return errors.Wrap(ErrFailedDashboardUpdate, err)
	}

	return nil
}

func (us *uiService) DeleteDashboard(token, dashboardID string) error {
	user, sdkerr := us.sdk.UserProfile(token)
	if sdkerr != nil {
		return errors.Wrap(ErrFailedRetrieveUserID, sdkerr)
	}

	if err := us.drepo.Delete(context.Background(), dashboardID, user.ID); err != nil {
		return errors.Wrap(ErrFailedDashboardDelete, err)
	}

	return nil
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
		"isset": func(name string, data interface{}) bool {
			v := reflect.ValueOf(data)
			if v.Kind() == reflect.Ptr {
				v = v.Elem()
			}

			if v.Kind() != reflect.Struct {
				return false
			}

			return v.FieldByName(name).IsValid()
		},
	})

	var tmplFiles []string
	for _, value := range templates {
		tmplFiles = append(tmplFiles, templatesDir+"/"+value+".html")
	}
	for _, value := range chartTemplates {
		tmplFiles = append(tmplFiles, chartTemplatesDir+"/"+value+".html")
	}
	tpl, err = tpl.ParseFiles(tmplFiles...)
	if err != nil {
		return nil, err
	}

	return tpl, nil
}
