// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package ui_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/0x6flab/namegenerator"
	"github.com/absmach/magistrala-ui/ui"
	"github.com/absmach/magistrala-ui/ui/mocks"
	"github.com/absmach/magistrala-ui/ui/oauth2"
	oauth2mocks "github.com/absmach/magistrala-ui/ui/oauth2/mocks"
	"github.com/absmach/magistrala/pkg/errors"
	sdk "github.com/absmach/magistrala/pkg/sdk/go"
	sdkmocks "github.com/absmach/magistrala/pkg/sdk/mocks"
	"github.com/absmach/magistrala/pkg/transformers/senml"
	"github.com/absmach/magistrala/pkg/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	idProvider   = uuid.New()
	prefix       = ""
	sdkmock      = new(sdkmocks.SDK)
	repo         = new(mocks.DashboardRepository)
	provider     = new(oauth2mocks.Provider)
	sdkerr       = errors.NewSDKError(fmt.Errorf("sdk error"))
	emailSuffix  = "@example.com"
	password     = "$tr0ngPassw0rd"
	namesgen     = namegenerator.NewGenerator()
	accessToken  = strings.Repeat("a", 32)
	name         = namesgen.Generate()
	id           = generateID(&testing.T{})
	validSession = ui.Session{
		User: ui.User{
			ID:       generateID(&testing.T{}),
			Name:     namesgen.Generate(),
			Identity: namesgen.Generate() + emailSuffix,
			Role:     "admin",
		},
		Domain: ui.Domain{
			ID:          generateID(&testing.T{}),
			Name:        namesgen.Generate(),
			Permissions: []string{"view", "edit"},
		},
		LoginStatus: ui.DomainLoginStatus,
		Token:       accessToken,
	}
	validUser = sdk.User{
		ID:   generateID(&testing.T{}),
		Name: namesgen.Generate(),
		Credentials: sdk.Credentials{
			Identity: namesgen.Generate() + emailSuffix,
			Secret:   password,
		},
		Tags: namesgen.GenerateMultiple(3),
		Metadata: map[string]interface{}{
			"key": "value",
		},
		CreatedAt: time.Now().Add(-time.Hour),
		UpdatedAt: time.Now(),
		Status:    "enabled",
		Role:      "admin",
	}
	validUsersPage = sdk.UsersPage{
		Users: []sdk.User{validUser},
	}
	validThing = sdk.Thing{
		ID:   generateID(&testing.T{}),
		Name: namesgen.Generate(),
		Credentials: sdk.Credentials{
			Identity: generateID(&testing.T{}),
			Secret:   generateID(&testing.T{}),
		},
		Tags: namesgen.GenerateMultiple(3),
		Metadata: map[string]interface{}{
			"key": "value",
		},
		CreatedAt:   time.Now().Add(-time.Hour),
		UpdatedAt:   time.Now(),
		Status:      "enabled",
		Permissions: []string{"view", "edit"},
	}
	validThingsPage = sdk.ThingsPage{
		Things: []sdk.Thing{validThing},
	}
	validChannel = sdk.Channel{
		ID:          generateID(&testing.T{}),
		DomainID:    generateID(&testing.T{}),
		ParentID:    generateID(&testing.T{}),
		Name:        namesgen.Generate(),
		Description: strings.Repeat("a", 100),
		Metadata: map[string]interface{}{
			"key": "value",
		},
		CreatedAt:   time.Now().Add(-time.Hour),
		UpdatedAt:   time.Now(),
		Status:      "enabled",
		Permissions: []string{"view", "edit"},
	}
	validChannelsPage = sdk.ChannelsPage{
		Channels: []sdk.Channel{validChannel},
	}
	validGroup = sdk.Group{
		ID:          generateID(&testing.T{}),
		DomainID:    generateID(&testing.T{}),
		ParentID:    generateID(&testing.T{}),
		Name:        namesgen.Generate(),
		Description: strings.Repeat("a", 100),
		Metadata: map[string]interface{}{
			"key": "value",
		},
		CreatedAt:   time.Now().Add(-time.Hour),
		UpdatedAt:   time.Now(),
		Status:      "enabled",
		Permissions: []string{"view", "edit"},
	}
	validGroupsPage = sdk.GroupsPage{
		Groups: []sdk.Group{validGroup},
	}
	value        = 10.0
	validMessage = sdk.MessagesPage{
		Messages: []senml.Message{
			{
				Channel:    generateID(&testing.T{}),
				Subtopic:   namesgen.Generate(),
				Publisher:  generateID(&testing.T{}),
				Protocol:   "mqtt",
				Name:       "temperature",
				Unit:       "C",
				Time:       float64(time.Now().UnixNano()),
				UpdateTime: float64(time.Now().UnixNano()),
				Value:      &value,
			},
			{
				Channel:   generateID(&testing.T{}),
				Subtopic:  namesgen.Generate(),
				Publisher: generateID(&testing.T{}),
				Protocol:  "mqtt",
				Name:      "temperature",
				Unit:      "C",
				Value:     &value,
			},
		},
	}
	validBootstrapConfig = sdk.BootstrapConfig{
		ExternalID:  generateID(&testing.T{}),
		ExternalKey: generateID(&testing.T{}),
		ThingID:     generateID(&testing.T{}),
		ThingKey:    generateID(&testing.T{}),
		Name:        namesgen.Generate(),
		Channels: []string{
			generateID(&testing.T{}),
		},
	}
	validBootstrapPage = sdk.BootstrapPage{
		Configs: []sdk.BootstrapConfig{validBootstrapConfig},
	}
	validDomain = sdk.Domain{
		ID:   generateID(&testing.T{}),
		Name: namesgen.Generate(),
		Metadata: map[string]interface{}{
			"key": "value",
		},
		Tags:        namesgen.GenerateMultiple(3),
		CreatedAt:   time.Now().Add(-time.Hour),
		CreatedBy:   generateID(&testing.T{}),
		UpdatedAt:   time.Now(),
		UpdatedBy:   generateID(&testing.T{}),
		Status:      "enabled",
		Alias:       namesgen.Generate(),
		Permissions: []string{"view", "edit"},
	}
	validDomainsPage = sdk.DomainsPage{
		Domains: []sdk.Domain{validDomain},
	}
	validDashboardReq = ui.DashboardReq{
		Name:        namesgen.Generate(),
		Description: strings.Repeat("a", 100),
		Layout:      strings.Repeat("a", 100),
		Metadata:    strings.Repeat("a", 100),
	}
	validUsersRelationReq = sdk.UsersRelationRequest{
		Relation: "viewer",
		UserIDs:  []string{generateID(&testing.T{})},
	}
	validUserGroupsReq = sdk.UserGroupsRequest{
		UserGroupIDs: []string{generateID(&testing.T{})},
	}
)

func init() {
	sdkmock.On("Health", "users").Return(sdk.HealthInfo{}, nil)
	sdkmock.On("Health", "things").Return(sdk.HealthInfo{}, nil)
	sdkmock.On("Health", "reader").Return(sdk.HealthInfo{}, nil)
	sdkmock.On("Health", "bootstrap").Return(sdk.HealthInfo{}, sdkerr)
}

func TestIndex(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc               string
		errUsers           errors.SDKError
		errEnabledUsers    errors.SDKError
		errGroups          errors.SDKError
		errEnabledGroup    errors.SDKError
		errThings          errors.SDKError
		errEnabledThings   errors.SDKError
		errChannels        errors.SDKError
		errEnabledChannels errors.SDKError
		err                error
	}{
		{
			desc: "success fetching users",
		},
		{
			desc:     "sdk error when fetching users",
			errUsers: sdkerr,
			err:      ui.ErrFailedRetreive,
		},
		{
			desc:            "sdk error when fetching enabled users",
			errEnabledUsers: sdkerr,
			err:             ui.ErrFailedRetreive,
		},
		{
			desc:      "sdk error when fetching groups",
			errGroups: sdkerr,
			err:       ui.ErrFailedRetreive,
		},
		{
			desc:            "sdk error when fetching enabled groups",
			errEnabledGroup: sdkerr,
			err:             ui.ErrFailedRetreive,
		},
		{
			desc:      "sdk error when fetching things",
			errThings: sdkerr,
			err:       ui.ErrFailedRetreive,
		},
		{
			desc:             "sdk error when fetching enabled things",
			errEnabledThings: sdkerr,
			err:              ui.ErrFailedRetreive,
		},
		{
			desc:        "sdk error when fetching channels",
			errChannels: sdkerr,
			err:         ui.ErrFailedRetreive,
		},
		{
			desc:               "sdk error when fetching enabled channels",
			errEnabledChannels: sdkerr,
			err:                ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			allPage := sdk.PageMetadata{
				Offset: 0,
				Status: "all",
			}
			enabledPage := allPage
			enabledPage.Status = "enabled"
			sdkCall := sdkmock.On("Users", allPage, validSession.Token).Return(validUsersPage, tc.errUsers)
			sdkCall1 := sdkmock.On("Users", enabledPage, validSession.Token).Return(validUsersPage, tc.errEnabledUsers)
			sdkCall2 := sdkmock.On("Groups", allPage, validSession.Token).Return(validGroupsPage, tc.errGroups)
			sdkCall3 := sdkmock.On("Groups", enabledPage, validSession.Token).Return(validGroupsPage, tc.errEnabledGroup)
			sdkCall4 := sdkmock.On("Things", allPage, validSession.Token).Return(validThingsPage, tc.errThings)
			sdkCall5 := sdkmock.On("Things", enabledPage, validSession.Token).Return(validThingsPage, tc.errEnabledThings)
			sdkCall6 := sdkmock.On("Channels", allPage, validSession.Token).Return(validChannelsPage, tc.errChannels)
			sdkCall7 := sdkmock.On("Channels", enabledPage, validSession.Token).Return(validChannelsPage, tc.errEnabledChannels)

			_, err := svc.Index(validSession)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			sdkCall.Unset()
			sdkCall1.Unset()
			sdkCall2.Unset()
			sdkCall3.Unset()
			sdkCall4.Unset()
			sdkCall5.Unset()
			sdkCall6.Unset()
			sdkCall7.Unset()
		})
	}
}

func TestViewRegistration(t *testing.T) {
	cases := []struct {
		desc string
		prov oauth2.Provider
		err  error
	}{
		{
			desc: "success",
			prov: provider,
			err:  nil,
		},
		{
			desc: "failed to execute due to missing provider",
			prov: nil,
			err:  ui.ErrExecTemplate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svc, err := ui.New(sdkmock, repo, idProvider, prefix, tc.prov)
			require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

			pcall := provider.On("IsEnabled").Return(true)
			pcall1 := provider.On("Name").Return(name)
			pcall2 := provider.On("Icon").Return("fa-test")
			page, err := svc.ViewRegistration()
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				assert.NotEmpty(t, page, "expected page to be not empty")
			}
			pcall.Unset()
			pcall1.Unset()
			pcall2.Unset()
		})
	}
}

func TestRegisterUser(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc          string
		errCreateUser errors.SDKError
		token         sdk.Token
		errLogin      error
		err           error
	}{
		{
			desc:          "success",
			errCreateUser: nil,
			token: sdk.Token{
				AccessToken:  accessToken,
				RefreshToken: accessToken,
				AccessType:   accessToken,
			},
			errLogin: nil,
			err:      nil,
		},
		{
			desc:          "failed to create user",
			errCreateUser: sdkerr,
			err:           ui.ErrFailedCreate,
		},
		{
			desc:          "failed to login",
			errCreateUser: nil,
			errLogin:      sdkerr,
			err:           ui.ErrToken,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			login := sdk.Login{
				Identity: validUser.Credentials.Identity,
				Secret:   validUser.Credentials.Secret,
			}
			sdkCall := sdkmock.On("CreateUser", validUser, "").Return(validUser, tc.errCreateUser)
			sdkCall1 := sdkmock.On("CreateToken", login).Return(tc.token, tc.errLogin)
			token, err := svc.RegisterUser(validUser)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "CreateUser", validUser, "")
				sdkCall1.Parent.AssertCalled(t, "CreateToken", login)
				require.Equal(t, tc.token, token, "expected token to be equal")
			}
			sdkCall.Unset()
			sdkCall1.Unset()
		})
	}
}

func TestLogin(t *testing.T) {
	provider.On("IsEnabled").Return(true)
	provider.On("Name").Return(name)
	provider.On("Icon").Return("fa-test")

	cases := []struct {
		desc string
		prov oauth2.Provider
		err  error
	}{
		{
			desc: "success",
			prov: provider,
			err:  nil,
		},
		{
			desc: "failed to execute due to missing provider",
			prov: nil,
			err:  ui.ErrExecTemplate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			svc, err := ui.New(sdkmock, repo, idProvider, prefix, tc.prov)
			require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

			page, err := svc.Login()
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				assert.NotEmpty(t, page, "expected page to be not empty")
			}
		})
	}
}

func TestPasswordResetRequest(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedResetRequest,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			email := namesgen.Generate() + emailSuffix
			sdkCall := sdkmock.On("ResetPasswordRequest", email).Return(tc.sdkerr)
			err := svc.PasswordResetRequest(email)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "ResetPasswordRequest", email)
			}
			sdkCall.Unset()
		})
	}
}

func TestPasswordReset(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedReset,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("ResetPassword", accessToken, password, password).Return(tc.sdkerr)
			err := svc.PasswordReset(accessToken, password, password)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "ResetPassword", accessToken, password, password)
			}
			sdkCall.Unset()
		})
	}
}

func TestShowPasswordReset(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
	provider.On("IsEnabled").Return(true)
	provider.On("Name").Return(name)
	provider.On("Icon").Return("fa-test")

	cases := []struct {
		desc string
		err  error
	}{
		{
			desc: "success",
			err:  nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			page, err := svc.ShowPasswordReset()
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				assert.NotEmpty(t, page, "expected page to be not empty")
			}
		})
	}
}

func TestPasswordUpdate(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
	provider.On("IsEnabled").Return(true)
	provider.On("Name").Return("test")
	provider.On("Icon").Return("fa-test")
	sdkmock.On("Health", "users").Return(sdk.HealthInfo{}, nil)
	sdkmock.On("Health", "things").Return(sdk.HealthInfo{}, nil)
	sdkmock.On("Health", "bootstrap").Return(sdk.HealthInfo{}, nil)

	cases := []struct {
		desc    string
		session ui.Session
		err     error
	}{
		{
			desc:    "success",
			session: validSession,
			err:     nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			page, err := svc.PasswordUpdate(tc.session)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				assert.NotEmpty(t, page, "expected page to be not empty")
			}
		})
	}
}

func TestUpdatePassword(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedUpdatePassword,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("UpdatePassword", password, password, accessToken).Return(validUser, tc.sdkerr)
			err := svc.UpdatePassword(accessToken, password, password)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "UpdatePassword", password, password, accessToken)
			}
			sdkCall.Unset()
		})
	}
}

func TestToken(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrToken,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			login := sdk.Login{Identity: validSession.User.Identity, Secret: password}
			sdkCall := sdkmock.On("CreateToken", login).Return(sdk.Token{}, tc.sdkerr)
			_, err := svc.Token(login)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "CreateToken", login)
			}
			sdkCall.Unset()
		})
	}
}

func TestRefreshToken(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrTokenRefresh,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("RefreshToken", sdk.Login{}, accessToken).Return(sdk.Token{}, tc.sdkerr)
			_, err := svc.RefreshToken(accessToken)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "RefreshToken", sdk.Login{}, accessToken)
			}
			sdkCall.Unset()
		})
	}
}

func TestDomainLogin(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrTokenRefresh,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("RefreshToken", sdk.Login{}, accessToken).Return(sdk.Token{}, tc.sdkerr)
			_, err := svc.DomainLogin(sdk.Login{}, accessToken)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "RefreshToken", sdk.Login{}, accessToken)
			}
			sdkCall.Unset()
		})
	}
}

func TestSession(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc           string
		errUserProfile errors.SDKError
		errDomain      errors.SDKError
		errPermissions errors.SDKError
		err            error
	}{
		{
			desc: "success",
		},
		{
			desc:           "sdk error on user profile",
			errUserProfile: sdkerr,
			err:            ui.ErrFailedRetreive,
		},
		{
			desc:      "sdk error on fetching domain",
			errDomain: sdkerr,
			err:       ui.ErrFailedRetreive,
		},
		{
			desc:           "sdk error on fetching domain permission",
			errPermissions: sdkerr,
			err:            ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("UserProfile", validSession.Token).Return(validUser, tc.errUserProfile)
			sdkCall1 := sdkmock.On("Domain", validSession.Domain.ID, validSession.Token).Return(validDomain, tc.errDomain)
			sdkCall2 := sdkmock.On("DomainPermissions", validSession.Domain.ID, validSession.Token).Return(validDomain, tc.errPermissions)
			_, err := svc.Session(validSession)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "UserProfile", validSession.Token)
				sdkCall1.Parent.AssertCalled(t, "Domain", validSession.Domain.ID, validSession.Token)
				sdkCall2.Parent.AssertCalled(t, "DomainPermissions", validSession.Domain.ID, validSession.Token)
			}
			sdkCall.Unset()
			sdkCall1.Unset()
			sdkCall2.Unset()
		})
	}
}

func TestCreateUsers(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedCreate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			users := []sdk.User{validUser}
			sdkCall := sdkmock.On("CreateUser", users[0], accessToken).Return(validUser, tc.sdkerr)
			err := svc.CreateUsers(accessToken, users...)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "CreateUser", users[0], accessToken)
			}
			sdkCall.Unset()
		})
	}
}

func TestListUsers(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("Users", sdk.PageMetadata{Offset: 0, Limit: 10, Status: "enabled"}, validSession.Token).Return(validUsersPage, tc.sdkerr)
			_, err := svc.ListUsers(validSession, "enabled", 1, 10)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "Users", sdk.PageMetadata{Offset: 0, Limit: 10, Status: "enabled"}, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestViewUser(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("User", id, validSession.Token).Return(validUser, tc.sdkerr)
			_, err := svc.ViewUser(validSession, id)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "User", id, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestUpdateUser(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedUpdate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("UpdateUser", validUser, validSession.Token).Return(validUser, tc.sdkerr)
			err := svc.UpdateUser(validSession.Token, validUser)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "UpdateUser", validUser, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestUpdateUserTags(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedUpdate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("UpdateUserTags", validUser, validSession.Token).Return(validUser, tc.sdkerr)
			err := svc.UpdateUserTags(validSession.Token, validUser)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "UpdateUserTags", validUser, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestUpdateUserIdentity(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedUpdate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("UpdateUserIdentity", validUser, validSession.Token).Return(validUser, tc.sdkerr)
			err := svc.UpdateUserIdentity(validSession.Token, validUser)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "UpdateUserIdentity", validUser, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestUpdateUserRole(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedUpdate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("UpdateUserRole", validUser, validSession.Token).Return(validUser, tc.sdkerr)
			err := svc.UpdateUserRole(validSession.Token, validUser)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "UpdateUserRole", validUser, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestEnableUser(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedEnable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("EnableUser", validUser.ID, validSession.Token).Return(validUser, tc.sdkerr)
			err := svc.EnableUser(validSession.Token, validUser.ID)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "EnableUser", validUser.ID, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestDisableUser(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedDisable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("DisableUser", validUser.ID, validSession.Token).Return(validUser, tc.sdkerr)
			err := svc.DisableUser(validSession.Token, validUser.ID)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "DisableUser", validUser.ID, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestCreateThing(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedCreate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("CreateThing", validThing, accessToken).Return(validThing, tc.sdkerr)
			err := svc.CreateThing(validThing, accessToken)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "CreateThing", validThing, accessToken)
			}
			sdkCall.Unset()
		})
	}
}

func TestCreateThings(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedCreate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			things := []sdk.Thing{validThing}
			sdkCall := sdkmock.On("CreateThing", things[0], accessToken).Return(validThing, tc.sdkerr)
			err := svc.CreateThings(accessToken, things...)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "CreateThing", things[0], accessToken)
			}
			sdkCall.Unset()
		})
	}
}

func TestListThings(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("Things", sdk.PageMetadata{Offset: 0, Limit: 10, Status: "enabled"}, validSession.Token).Return(validThingsPage, tc.sdkerr)
			_, err := svc.ListThings(validSession, "enabled", 1, 10)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "Things", sdk.PageMetadata{Offset: 0, Limit: 10, Status: "enabled"}, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestViewThing(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc           string
		errThing       errors.SDKError
		errPermissions errors.SDKError
		err            error
	}{
		{
			desc: "success",
		},
		{
			desc:     "sdk error on fetching thing",
			errThing: sdkerr,
			err:      ui.ErrFailedRetreive,
		},
		{
			desc:           "sdk error on fetching thing permission",
			errPermissions: sdkerr,
			err:            ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("Thing", id, validSession.Token).Return(validThing, tc.errThing)
			sdkCall1 := sdkmock.On("ThingPermissions", id, validSession.Token).Return(validThing, tc.errPermissions)
			_, err := svc.ViewThing(validSession, id)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "Thing", id, validSession.Token)
			}
			sdkCall.Unset()
			sdkCall1.Unset()
		})
	}
}

func TestUpdateThing(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedUpdate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("UpdateThing", validThing, validSession.Token).Return(validThing, tc.sdkerr)
			err := svc.UpdateThing(validSession.Token, validThing)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "UpdateThing", validThing, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestUpdateThingTags(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedUpdate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("UpdateThingTags", validThing, validSession.Token).Return(validThing, tc.sdkerr)
			err := svc.UpdateThingTags(validSession.Token, validThing)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "UpdateThingTags", validThing, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestUpdateThingSecret(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedUpdate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("UpdateThingSecret", validThing.ID, validThing.Credentials.Secret, validSession.Token).Return(validThing, tc.sdkerr)
			err := svc.UpdateThingSecret(validSession.Token, validThing)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "UpdateThingSecret", validThing.ID, validThing.Credentials.Secret, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestEnableThing(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedEnable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("EnableThing", validThing.ID, validSession.Token).Return(validThing, tc.sdkerr)
			err := svc.EnableThing(validSession.Token, validThing.ID)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "EnableThing", validThing.ID, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestDisableThing(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedDisable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("DisableThing", validThing.ID, validSession.Token).Return(validThing, tc.sdkerr)
			err := svc.DisableThing(validSession.Token, validThing.ID)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "DisableThing", validThing.ID, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestShareThing(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedShare,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("ShareThing", validThing.ID, validUsersRelationReq, validSession.Token).Return(tc.sdkerr)
			err := svc.ShareThing(validSession.Token, validThing.ID, validUsersRelationReq)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "ShareThing", validThing.ID, validUsersRelationReq, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestUnshareThing(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedUnshare,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("UnshareThing", validThing.ID, validUsersRelationReq, validSession.Token).Return(tc.sdkerr)
			err := svc.UnshareThing(validSession.Token, validThing.ID, validUsersRelationReq)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "UnshareThing", validThing.ID, validUsersRelationReq, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestListThingUsers(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc              string
		errListThingUsers errors.SDKError
		errPermissions    errors.SDKError
		err               error
	}{
		{
			desc: "success",
		},
		{
			desc:              "sdk error on fetching thing",
			errListThingUsers: sdkerr,
			err:               ui.ErrFailedRetreive,
		},
		{
			desc:           "sdk error on fetching thing permission",
			errPermissions: sdkerr,
			err:            ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			page := sdk.PageMetadata{
				Offset:     0,
				Limit:      10,
				Permission: "view",
			}
			sdkCall := sdkmock.On("ListThingUsers", id, page, validSession.Token).Return(validUsersPage, tc.errListThingUsers)
			sdkCall1 := sdkmock.On("ThingPermissions", id, validSession.Token).Return(validThing, tc.errPermissions)
			_, err := svc.ListThingUsers(validSession, id, "view", 1, 10)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "ListThingUsers", id, page, validSession.Token)
			}
			sdkCall.Unset()
			sdkCall1.Unset()
		})
	}
}

func TestListChannelsByThing(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc                string
		errListChannelUsers errors.SDKError
		errPermissions      errors.SDKError
		errThing            errors.SDKError
		err                 error
	}{
		{
			desc: "success",
		},
		{
			desc:                "sdk error on fetching thing",
			errListChannelUsers: sdkerr,
			err:                 ui.ErrFailedRetreive,
		},
		{
			desc:           "sdk error on fetching thing permission",
			errPermissions: sdkerr,
			err:            ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			page := sdk.PageMetadata{
				Offset:     0,
				Limit:      10,
				Visibility: "all",
			}
			sdkCall := sdkmock.On("ChannelsByThing", id, page, validSession.Token).Return(validChannelsPage, tc.errListChannelUsers)
			sdkCall1 := sdkmock.On("ThingPermissions", id, validSession.Token).Return(validThing, tc.errPermissions)
			sdkCall2 := sdkmock.On("Thing", id, validSession.Token).Return(validThing, tc.errPermissions)
			_, err := svc.ListChannelsByThing(validSession, id, 1, 10)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "ChannelsByThing", id, page, validSession.Token)
				sdkCall1.Parent.AssertCalled(t, "ThingPermissions", id, validSession.Token)
				sdkCall2.Parent.AssertCalled(t, "Thing", id, validSession.Token)
			}
			sdkCall.Unset()
			sdkCall1.Unset()
			sdkCall2.Unset()
		})
	}
}

func TestCreateChannel(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedCreate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("CreateChannel", validChannel, accessToken).Return(validChannel, tc.sdkerr)
			err := svc.CreateChannel(validChannel, accessToken)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "CreateChannel", validChannel, accessToken)
			}
			sdkCall.Unset()
		})
	}
}

func TestCreateChannels(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedCreate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			channels := []sdk.Channel{validChannel}
			sdkCall := sdkmock.On("CreateChannel", channels[0], accessToken).Return(validChannel, tc.sdkerr)
			err := svc.CreateChannels(accessToken, channels...)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "CreateChannel", channels[0], accessToken)
			}
			sdkCall.Unset()
		})
	}
}

func TestListChannels(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("Channels", sdk.PageMetadata{Offset: 0, Limit: 10, Status: "enabled"}, validSession.Token).Return(validChannelsPage, tc.sdkerr)
			_, err := svc.ListChannels(validSession, "enabled", 1, 10)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "Channels", sdk.PageMetadata{Offset: 0, Limit: 10, Status: "enabled"}, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestViewChannel(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc           string
		errChannel     errors.SDKError
		errPermissions errors.SDKError
		err            error
	}{
		{
			desc: "success",
		},
		{
			desc:       "sdk error on fetching channel",
			errChannel: sdkerr,
			err:        ui.ErrFailedRetreive,
		},
		{
			desc:           "sdk error on fetching channel permissions",
			errPermissions: sdkerr,
			err:            ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("Channel", id, validSession.Token).Return(validChannel, tc.errChannel)
			sdkCall1 := sdkmock.On("ChannelPermissions", id, validSession.Token).Return(validChannel, tc.errPermissions)
			_, err := svc.ViewChannel(validSession, id)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "Channel", id, validSession.Token)
			}
			sdkCall.Unset()
			sdkCall1.Unset()
		})
	}
}

func TestUpdateChannel(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedUpdate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("UpdateChannel", validChannel, validSession.Token).Return(validChannel, tc.sdkerr)
			err := svc.UpdateChannel(validSession.Token, validChannel)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "UpdateChannel", validChannel, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestListThingsByChannel(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc                  string
		errListThingByChannel errors.SDKError
		errPermissions        errors.SDKError
		err                   error
	}{
		{
			desc: "success",
		},
		{
			desc:                  "sdk error on fetching channel",
			errListThingByChannel: sdkerr,
			err:                   ui.ErrFailedRetreive,
		},
		{
			desc:           "sdk error on fetching channel permission",
			errPermissions: sdkerr,
			err:            ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			page := sdk.PageMetadata{
				Offset:     0,
				Limit:      10,
				Visibility: "all",
			}
			sdkCall := sdkmock.On("ThingsByChannel", id, page, validSession.Token).Return(validThingsPage, tc.errListThingByChannel)
			sdkCall1 := sdkmock.On("ChannelPermissions", id, validSession.Token).Return(validChannel, tc.errPermissions)
			_, err := svc.ListThingsByChannel(validSession, id, 1, 10)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "ThingsByChannel", id, page, validSession.Token)
				sdkCall1.Parent.AssertCalled(t, "ChannelPermissions", id, validSession.Token)
			}
			sdkCall.Unset()
			sdkCall1.Unset()
		})
	}
}

func TestEnableChannel(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedEnable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("EnableChannel", validChannel.ID, validSession.Token).Return(validChannel, tc.sdkerr)
			err := svc.EnableChannel(validSession.Token, validChannel.ID)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "EnableChannel", validChannel.ID, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestDisableChannel(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedDisable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("DisableChannel", validChannel.ID, validSession.Token).Return(validChannel, tc.sdkerr)
			err := svc.DisableChannel(validSession.Token, validChannel.ID)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "DisableChannel", validChannel.ID, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestConnect(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedConnect,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("Connect", sdk.Connection{}, validSession.Token).Return(tc.sdkerr)
			err := svc.Connect(validSession.Token, sdk.Connection{})
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "Connect", sdk.Connection{}, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestDisconnect(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedDisconnect,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("Disconnect", sdk.Connection{}, validSession.Token).Return(tc.sdkerr)
			err := svc.Disconnect(validSession.Token, sdk.Connection{})
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "Disconnect", sdk.Connection{}, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestConnectThing(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedConnect,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("ConnectThing", id, id, validSession.Token).Return(tc.sdkerr)
			err := svc.ConnectThing(id, id, validSession.Token)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "ConnectThing", id, id, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestDisconnectThing(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedDisconnect,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("DisconnectThing", id, id, validSession.Token).Return(tc.sdkerr)
			err := svc.DisconnectThing(id, id, validSession.Token)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "DisconnectThing", id, id, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestAddUserToChannel(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedAssign,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("AddUserToChannel", id, validUsersRelationReq, validSession.Token).Return(tc.sdkerr)
			err := svc.AddUserToChannel(validSession.Token, id, validUsersRelationReq)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "AddUserToChannel", id, validUsersRelationReq, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestRemoveUserFromChannel(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedUnassign,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("RemoveUserFromChannel", id, validUsersRelationReq, validSession.Token).Return(tc.sdkerr)
			err := svc.RemoveUserFromChannel(validSession.Token, id, validUsersRelationReq)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "RemoveUserFromChannel", id, validUsersRelationReq, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestListChannelUsers(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc                string
		errListChannelUsers errors.SDKError
		errPermissions      errors.SDKError
		err                 error
	}{
		{
			desc: "success",
		},
		{
			desc:                "sdk error on fetching thing",
			errListChannelUsers: sdkerr,
			err:                 ui.ErrFailedRetreive,
		},
		{
			desc:           "sdk error on fetching thing permission",
			errPermissions: sdkerr,
			err:            ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			page := sdk.PageMetadata{
				Offset:     0,
				Limit:      10,
				Permission: "view",
			}
			sdkCall := sdkmock.On("ListChannelUsers", id, page, validSession.Token).Return(validUsersPage, tc.errListChannelUsers)
			sdkCall1 := sdkmock.On("ChannelPermissions", id, validSession.Token).Return(validChannel, tc.errPermissions)
			_, err := svc.ListChannelUsers(validSession, id, "view", 1, 10)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "ListChannelUsers", id, page, validSession.Token)
			}
			sdkCall.Unset()
			sdkCall1.Unset()
		})
	}
}

func TestAddUserGroupToChannel(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedAssign,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("AddUserGroupToChannel", id, validUserGroupsReq, validSession.Token).Return(tc.sdkerr)
			err := svc.AddUserGroupToChannel(validSession.Token, id, validUserGroupsReq)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "AddUserGroupToChannel", id, validUserGroupsReq, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestRemoveUserGroupFromChannel(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedUnassign,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("RemoveUserGroupFromChannel", id, validUserGroupsReq, validSession.Token).Return(tc.sdkerr)
			err := svc.RemoveUserGroupFromChannel(validSession.Token, id, validUserGroupsReq)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "RemoveUserGroupFromChannel", id, validUserGroupsReq, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestListChannelUserGroups(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc                     string
		errListChannelUserGroups errors.SDKError
		errPermissions           errors.SDKError
		err                      error
	}{
		{
			desc: "success",
		},
		{
			desc:                     "sdk error on fetching thing",
			errListChannelUserGroups: sdkerr,
			err:                      ui.ErrFailedRetreive,
		},
		{
			desc:           "sdk error on fetching thing permission",
			errPermissions: sdkerr,
			err:            ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			page := sdk.PageMetadata{
				Offset: 0,
				Limit:  10,
			}
			sdkCall := sdkmock.On("ListChannelUserGroups", id, page, validSession.Token).Return(validGroupsPage, tc.errListChannelUserGroups)
			sdkCall1 := sdkmock.On("ChannelPermissions", id, validSession.Token).Return(validChannel, tc.errPermissions)
			_, err := svc.ListChannelUserGroups(validSession, id, 1, 10)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "ListChannelUserGroups", id, page, validSession.Token)
			}
			sdkCall.Unset()
			sdkCall1.Unset()
		})
	}
}

func TestAssign(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedAssign,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("AddUserToGroup", id, validUsersRelationReq, validSession.Token).Return(tc.sdkerr)
			err := svc.Assign(validSession.Token, id, validUsersRelationReq)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "AddUserToGroup", id, validUsersRelationReq, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestUnassign(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedUnassign,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("RemoveUserFromGroup", id, validUsersRelationReq, validSession.Token).Return(tc.sdkerr)
			err := svc.Unassign(validSession.Token, id, validUsersRelationReq)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "RemoveUserFromGroup", id, validUsersRelationReq, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestCreateGroups(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedCreate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			groups := []sdk.Group{validGroup}
			sdkCall := sdkmock.On("CreateGroup", groups[0], accessToken).Return(validGroup, tc.sdkerr)
			err := svc.CreateGroups(accessToken, groups...)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "CreateGroup", groups[0], accessToken)
			}
			sdkCall.Unset()
		})
	}
}

func TestListGroupUsers(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc              string
		errListGroupUsers errors.SDKError
		errPermissions    errors.SDKError
		err               error
	}{
		{
			desc: "success",
		},
		{
			desc:              "sdk error on fetching thing",
			errListGroupUsers: sdkerr,
			err:               ui.ErrFailedRetreive,
		},
		{
			desc:           "sdk error on fetching thing permission",
			errPermissions: sdkerr,
			err:            ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			page := sdk.PageMetadata{
				Offset:     0,
				Limit:      10,
				Visibility: "all",
				Permission: "view",
			}
			sdkCall := sdkmock.On("ListGroupUsers", id, page, validSession.Token).Return(validUsersPage, tc.errListGroupUsers)
			sdkCall1 := sdkmock.On("GroupPermissions", id, validSession.Token).Return(validGroup, tc.errPermissions)
			_, err := svc.ListGroupUsers(validSession, id, "view", 1, 10)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "ListGroupUsers", id, page, validSession.Token)
			}
			sdkCall.Unset()
			sdkCall1.Unset()
		})
	}
}

func TestViewGroup(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc           string
		errGroup       errors.SDKError
		errParent      errors.SDKError
		errPermissions errors.SDKError
		err            error
	}{
		{
			desc:     "success",
			errGroup: nil,
			err:      nil,
		},
		{
			desc:     "sdk error due to fetching group",
			errGroup: sdkerr,
			err:      ui.ErrFailedRetreive,
		},
		{
			desc:      "sdk error due to fetching parent",
			errParent: sdkerr,
			err:       ui.ErrFailedRetreive,
		},
		{
			desc:           "sdk error due to fetching group permissions",
			errPermissions: sdkerr,
			err:            ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("Group", id, validSession.Token).Return(validGroup, tc.errGroup)
			sdkCall1 := sdkmock.On("Group", validGroup.ParentID, validSession.Token).Return(validGroup, tc.errParent)
			sdkCall2 := sdkmock.On("GroupPermissions", id, validSession.Token).Return(validGroup, tc.errPermissions)
			_, err := svc.ViewGroup(validSession, id)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "Group", id, validSession.Token)
			}
			sdkCall.Unset()
			sdkCall1.Unset()
			sdkCall2.Unset()
		})
	}
}

func TestListGroups(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("Groups", sdk.PageMetadata{Offset: 0, Limit: 10, Status: "enabled"}, validSession.Token).Return(validGroupsPage, tc.sdkerr)
			_, err := svc.ListGroups(validSession, "enabled", 1, 10)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "Groups", sdk.PageMetadata{Offset: 0, Limit: 10, Status: "enabled"}, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestUpdateGroup(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedUpdate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("UpdateGroup", validGroup, validSession.Token).Return(validGroup, tc.sdkerr)
			err := svc.UpdateGroup(validSession.Token, validGroup)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "UpdateGroup", validGroup, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestEnableGroup(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedEnable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("EnableGroup", validGroup.ID, validSession.Token).Return(validGroup, tc.sdkerr)
			err := svc.EnableGroup(validSession.Token, validGroup.ID)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "EnableGroup", validGroup.ID, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestDisableGroup(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedDisable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("DisableGroup", validGroup.ID, validSession.Token).Return(validGroup, tc.sdkerr)
			err := svc.DisableGroup(validSession.Token, validGroup.ID)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "DisableGroup", validGroup.ID, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestListUserGroupChannels(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc                     string
		errListUserGroupChannels errors.SDKError
		errPermissions           errors.SDKError
		err                      error
	}{
		{
			desc: "success",
		},
		{
			desc:                     "sdk error on fetching thing",
			errListUserGroupChannels: sdkerr,
			err:                      ui.ErrFailedRetreive,
		},
		{
			desc:           "sdk error on fetching thing permission",
			errPermissions: sdkerr,
			err:            ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			page := sdk.PageMetadata{
				Offset: 0,
				Limit:  10,
			}
			sdkCall := sdkmock.On("ListGroupChannels", id, page, validSession.Token).Return(validGroupsPage, tc.errListUserGroupChannels)
			sdkCall1 := sdkmock.On("GroupPermissions", id, validSession.Token).Return(validGroup, tc.errPermissions)
			_, err := svc.ListUserGroupChannels(validSession, id, 1, 10)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "ListGroupChannels", id, page, validSession.Token)
			}
			sdkCall.Unset()
			sdkCall1.Unset()
		})
	}
}

func TestReadMessages(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("ReadMessages", sdk.MessagePageMetadata{}, id, validSession.Token).Return(validMessage, tc.sdkerr)
			_, err := svc.ReadMessages(validSession, id, id, sdk.MessagePageMetadata{})
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "ReadMessages", sdk.MessagePageMetadata{}, id, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestFetchChartData(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("ReadMessages", sdk.MessagePageMetadata{}, id, accessToken).Return(validMessage, tc.sdkerr)
			_, err := svc.FetchChartData(accessToken, id, sdk.MessagePageMetadata{})
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "ReadMessages", sdk.MessagePageMetadata{}, id, accessToken)
			}
			sdkCall.Unset()
		})
	}
}

func TestPublish(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedPublish,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			data, err := json.Marshal(ui.Message{})
			require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

			sdkCall := sdkmock.On("SendMessage", id, "["+string(data)+"]", id).Return(tc.sdkerr)
			sdkerr := svc.Publish(id, id, ui.Message{})
			assert.True(t, errors.Contains(sdkerr, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, sdkerr))
			if sdkerr == nil {
				sdkCall.Parent.AssertCalled(t, "SendMessage", id, "["+string(data)+"]", id)
			}
			sdkCall.Unset()
		})
	}
}

func TestCreateBootstrap(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedCreate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("AddBootstrap", validBootstrapConfig, accessToken).Return("", tc.sdkerr)
			err := svc.CreateBootstrap(accessToken, validBootstrapConfig)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "AddBootstrap", validBootstrapConfig, accessToken)
			}
			sdkCall.Unset()
		})
	}
}

func TestListBootstrap(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc         string
		errBootstrap errors.SDKError
		errThings    errors.SDKError
		err          error
	}{
		{
			desc: "success",
		},
		{
			desc:         "sdk error due to fetching bootstrap",
			errBootstrap: sdkerr,
			err:          ui.ErrFailedRetreive,
		},
		{
			desc:      "sdk error due to fetching thing",
			errThings: sdkerr,
			err:       ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			page := sdk.PageMetadata{
				Offset:     0,
				Limit:      10,
				Visibility: "all",
			}
			sdkCall := sdkmock.On("Bootstraps", page, validSession.Token).Return(validBootstrapPage, tc.errBootstrap)
			filter := sdk.PageMetadata{
				Offset: uint64(0),
				Total:  uint64(100),
				Limit:  uint64(100),
			}
			sdkCall1 := sdkmock.On("Things", filter, validSession.Token).Return(validThingsPage, tc.errThings)
			_, err := svc.ListBootstrap(validSession, 1, 10)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "Bootstraps", page, validSession.Token)
				sdkCall1.Parent.AssertCalled(t, "Things", filter, validSession.Token)
			}
			sdkCall.Unset()
			sdkCall1.Unset()
		})
	}
}

func TestUpdateBootstrap(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedUpdate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("UpdateBootstrap", validBootstrapConfig, validSession.Token).Return(tc.sdkerr)
			err := svc.UpdateBootstrap(validSession.Token, validBootstrapConfig)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "UpdateBootstrap", validBootstrapConfig, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestUpdateBootstrapConnections(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		conf   sdk.BootstrapConfig
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			conf:   validBootstrapConfig,
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			conf:   validBootstrapConfig,
			sdkerr: sdkerr,
			err:    ui.ErrFailedUpdate,
		},
		{
			desc: "invalid bootstrap config",
			conf: sdk.BootstrapConfig{
				Channels: validChannel,
			},
			err: ui.ErrFailedUpdate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("UpdateBootstrapConnection", tc.conf.ThingID, tc.conf.Channels, validSession.Token).Return(tc.sdkerr)
			err := svc.UpdateBootstrapConnections(validSession.Token, tc.conf)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "UpdateBootstrapConnection", tc.conf.ThingID, tc.conf.Channels, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestUpdateBootstrapCerts(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedUpdate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("UpdateBootstrapCerts", validBootstrapConfig.ThingID, validBootstrapConfig.ClientCert, validBootstrapConfig.ClientKey, validBootstrapConfig.CACert, validSession.Token).Return(validBootstrapConfig, tc.sdkerr)
			err := svc.UpdateBootstrapCerts(validSession.Token, validBootstrapConfig)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "UpdateBootstrapCerts", validBootstrapConfig.ThingID, validBootstrapConfig.ClientCert, validBootstrapConfig.ClientKey, validBootstrapConfig.CACert, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestDeleteBootstrap(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedDelete,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("RemoveBootstrap", validBootstrapConfig.ThingID, validSession.Token).Return(tc.sdkerr)
			err := svc.DeleteBootstrap(validSession.Token, validBootstrapConfig.ThingID)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "RemoveBootstrap", validBootstrapConfig.ThingID, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestUpdateBootstrapState(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedUpdate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("Whitelist", validBootstrapConfig, validSession.Token).Return(tc.sdkerr)
			err := svc.UpdateBootstrapState(validSession.Token, validBootstrapConfig)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "Whitelist", validBootstrapConfig, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestViewBootstrap(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc         string
		conf         sdk.BootstrapConfig
		errBootstrap errors.SDKError
		errThing     errors.SDKError
		err          error
	}{
		{
			desc: "success",
		},
		{
			desc: "success with channel as an array of sdk.Channel",
			conf: sdk.BootstrapConfig{
				Channels: []sdk.Channel{validChannel},
			},
		},
		{
			desc: "success with channel as an array of string",
			conf: sdk.BootstrapConfig{
				Channels: []string{validChannel.ID},
			},
		},
		{
			desc: "success with channel as nil",
			conf: sdk.BootstrapConfig{
				Channels: nil,
			},
		},
		{
			desc: "success with invalid channel",
			conf: sdk.BootstrapConfig{
				Channels: 1,
			},
			err: ui.ErrFailedRetreive,
		},
		{
			desc:         "sdk error on fetching bootstrap",
			errBootstrap: sdkerr,
			err:          ui.ErrFailedRetreive,
		},
		{
			desc:     "sdk error on fetching thing ",
			errThing: sdkerr,
			err:      ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("ViewBootstrap", id, validSession.Token).Return(tc.conf, tc.errBootstrap)
			sdkCall1 := sdkmock.On("Thing", id, validSession.Token).Return(validThing, tc.errThing)
			_, err := svc.ViewBootstrap(validSession, id)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "ViewBootstrap", id, validSession.Token)
				sdkCall1.Parent.AssertCalled(t, "Thing", id, validSession.Token)
			}
			sdkCall.Unset()
			sdkCall1.Unset()
		})
	}
}

func TestGetRemoteTerminal(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc string
		prov oauth2.Provider
		err  error
	}{
		{
			desc: "success",
			prov: provider,
			err:  nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			page, err := svc.GetRemoteTerminal(validSession, "test")
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				assert.NotEmpty(t, page, "expected page to be not empty")
			}
		})
	}
}

func TestGetEntities(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		entity string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success fetching users",
			entity: "users",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error when fetching users",
			entity: "users",
			sdkerr: sdkerr,
			err:    ui.ErrFailedRetreive,
		},
		{
			desc:   "success fetching groups",
			entity: "groups",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error when fetching groups",
			entity: "groups",
			sdkerr: sdkerr,
			err:    ui.ErrFailedRetreive,
		},
		{
			desc:   "success fetching things",
			entity: "things",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error when fetching things",
			entity: "things",
			sdkerr: sdkerr,
			err:    ui.ErrFailedRetreive,
		},
		{
			desc:   "success fetching channels",
			entity: "channels",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error when fetching channels",
			entity: "channels",
			sdkerr: sdkerr,
			err:    ui.ErrFailedRetreive,
		},
		{
			desc:   "success fetching members",
			entity: "members",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error when fetching members",
			entity: "members",
			sdkerr: sdkerr,
			err:    ui.ErrFailedRetreive,
		},
		{
			desc:   "success fetching domains",
			entity: "domains",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error when fetching domains",
			entity: "domains",
			sdkerr: sdkerr,
			err:    ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			page := sdk.PageMetadata{
				Offset:     0,
				Limit:      10,
				Name:       name,
				Permission: "view",
			}
			switch tc.entity {
			case "users":
				sdkCall := sdkmock.On("Users", page, accessToken).Return(validUsersPage, tc.sdkerr)
				defer sdkCall.Unset()
			case "groups":
				sdkCall := sdkmock.On("Groups", page, accessToken).Return(validGroupsPage, tc.sdkerr)
				defer sdkCall.Unset()
			case "things":
				sdkCall := sdkmock.On("Things", page, accessToken).Return(validThingsPage, tc.sdkerr)
				defer sdkCall.Unset()
			case "channels":
				sdkCall := sdkmock.On("Channels", page, accessToken).Return(validChannelsPage, tc.sdkerr)
				defer sdkCall.Unset()
			case "members":
				sdkCall := sdkmock.On("ListDomainUsers", id, page, accessToken).Return(validUsersPage, tc.sdkerr)
				defer sdkCall.Unset()
			case "domains":
				sdkCall := sdkmock.On("Domains", page, accessToken).Return(validDomainsPage, tc.sdkerr)
				defer sdkCall.Unset()
			}
			_, err := svc.GetEntities(accessToken, tc.entity, name, id, "view", 1, 10)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
		})
	}
}

func TestErrorPage(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc    string
		message string
		url     string
		err     error
	}{
		{
			desc:    "success",
			message: "test",
			url:     "test",
			err:     nil,
		},
		{
			desc:    "with empty message and url",
			message: "",
			url:     "",
			err:     nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			page, err := svc.ErrorPage(tc.message, tc.url)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				assert.NotEmpty(t, page, "expected page to be not empty")
			}
		})
	}
}

func TestCreateDomain(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedCreate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("CreateDomain", validDomain, accessToken).Return(validDomain, tc.sdkerr)
			err := svc.CreateDomain(accessToken, validDomain)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "CreateDomain", validDomain, accessToken)
			}
			sdkCall.Unset()
		})
	}
}

func TestListDomains(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("Domains", sdk.PageMetadata{Offset: 0, Limit: 10, Status: "enabled"}, validSession.Token).Return(validDomainsPage, tc.sdkerr)
			_, err := svc.ListDomains(validSession, "enabled", 1, 10)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "Domains", sdk.PageMetadata{Offset: 0, Limit: 10, Status: "enabled"}, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestDomain(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc           string
		errDomain      errors.SDKError
		errPermissions errors.SDKError
		err            error
	}{
		{
			desc: "success",
		},
		{
			desc:      "sdk error on fetching domain",
			errDomain: sdkerr,
			err:       ui.ErrFailedRetreive,
		},
		{
			desc:           "sdk error on fetching domain permission",
			errPermissions: sdkerr,
			err:            ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("Domain", validSession.Domain.ID, validSession.Token).Return(validDomain, tc.errDomain)
			sdkCall1 := sdkmock.On("DomainPermissions", validSession.Domain.ID, validSession.Token).Return(validDomain, tc.errPermissions)
			_, err := svc.Domain(validSession)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "Domain", validSession.Domain.ID, validSession.Token)
			}
			sdkCall.Unset()
			sdkCall1.Unset()
		})
	}
}

func TestUpdateDomain(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedUpdate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("UpdateDomain", validDomain, validSession.Token).Return(validDomain, tc.sdkerr)
			err := svc.UpdateDomain(validSession.Token, validDomain)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "UpdateDomain", validDomain, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestEnableDomain(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedEnable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("EnableDomain", validDomain.ID, validSession.Token).Return(tc.sdkerr)
			err := svc.EnableDomain(validSession.Token, validDomain.ID)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "EnableDomain", validDomain.ID, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestDisableDomain(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedDisable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("DisableDomain", validDomain.ID, validSession.Token).Return(tc.sdkerr)
			err := svc.DisableDomain(validSession.Token, validDomain.ID)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "DisableDomain", validDomain.ID, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestAssignMember(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedAssign,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("AddUserToDomain", validDomain.ID, validUsersRelationReq, validSession.Token).Return(tc.sdkerr)
			err := svc.AssignMember(validSession.Token, validDomain.ID, validUsersRelationReq)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "AddUserToDomain", validDomain.ID, validUsersRelationReq, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestUnassignMember(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc:   "success",
			sdkerr: nil,
			err:    nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedUnassign,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("RemoveUserFromDomain", validDomain.ID, validUsersRelationReq, validSession.Token).Return(tc.sdkerr)
			err := svc.UnassignMember(validSession.Token, validDomain.ID, validUsersRelationReq)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "RemoveUserFromDomain", validDomain.ID, validUsersRelationReq, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestViewMember(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc      string
		usersPage sdk.UsersPage
		sdkerr    errors.SDKError
		err       error
	}{
		{
			desc:      "success",
			usersPage: sdk.UsersPage{Users: []sdk.User{validUser}},
			sdkerr:    nil,
			err:       nil,
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedRetreive,
		},
		{
			desc: "empty users",
			err:  ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("Users", sdk.PageMetadata{Identity: "test", Limit: 1}, validSession.Token).Return(tc.usersPage, tc.sdkerr)
			_, err := svc.ViewMember(validSession, "test")
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "Users", sdk.PageMetadata{Identity: "test", Limit: 1}, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestMembers(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc: "success",
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("ListDomainUsers", validSession.Domain.ID, sdk.PageMetadata{Offset: 0, Limit: 10}, validSession.Token).Return(validUsersPage, tc.sdkerr)
			_, err := svc.Members(validSession, 1, 10)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "ListDomainUsers", validSession.Domain.ID, sdk.PageMetadata{Offset: 0, Limit: 10}, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestSendInvitation(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc: "success",
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedSend,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("SendInvitation", sdk.Invitation{}, validSession.Token).Return(tc.sdkerr)
			err := svc.SendInvitation(validSession.Token, sdk.Invitation{})
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "SendInvitation", sdk.Invitation{}, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestInvitations(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc: "success",
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			page := sdk.PageMetadata{
				Offset:   0,
				Limit:    10,
				DomainID: "test",
				State:    "pending",
			}
			sdkCall := sdkmock.On("Invitations", page, validSession.Token).Return(sdk.InvitationPage{}, tc.sdkerr)
			_, err := svc.Invitations(validSession, "test", 1, 10)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "Invitations", page, validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestAcceptInvitation(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc: "success",
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedAccept,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("AcceptInvitation", "test", validSession.Token).Return(tc.sdkerr)
			err := svc.AcceptInvitation(validSession.Token, "test")
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "AcceptInvitation", "test", validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestDeleteInvitation(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc   string
		sdkerr errors.SDKError
		err    error
	}{
		{
			desc: "success",
		},
		{
			desc:   "sdk error",
			sdkerr: sdkerr,
			err:    ui.ErrFailedDelete,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("DeleteInvitation", "test", "test", validSession.Token).Return(tc.sdkerr)
			err := svc.DeleteInvitation(validSession.Token, "test", "test")
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "DeleteInvitation", "test", "test", validSession.Token)
			}
			sdkCall.Unset()
		})
	}
}

func TestCreateDashboard(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc           string
		errUserProfile errors.SDKError
		errCreate      error
		err            error
	}{
		{
			desc: "success",
		},
		{
			desc:           "sdk error",
			errUserProfile: sdkerr,
			err:            ui.ErrFailedRetrieveUserID,
		},
		{
			desc:      "failed to create dashboard",
			errCreate: fmt.Errorf("failed to create dashboard"),
			err:       ui.ErrFailedDashboardSave,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("UserProfile", validSession.Token).Return(validUser, tc.errUserProfile)
			repoCall := repo.On("Create", context.Background(), mock.Anything).Return(ui.Dashboard{}, tc.errCreate)
			_, err := svc.CreateDashboard(context.Background(), validSession.Token, validDashboardReq)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "UserProfile", validSession.Token)
				repoCall.Parent.AssertCalled(t, "Create", context.Background(), mock.Anything)
			}
			sdkCall.Unset()
			repoCall.Unset()
		})
	}
}

func TestViewDashboard(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc           string
		errUserProfile errors.SDKError
		errView        error
		err            error
	}{
		{
			desc: "success",
		},
		{
			desc:           "sdk error",
			errUserProfile: sdkerr,
			err:            ui.ErrFailedRetrieveUserID,
		},
		{
			desc:    "failed to view dashboard",
			errView: fmt.Errorf("failed to view dashboard"),
			err:     ui.ErrFailedDashboardRetrieve,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("UserProfile", validSession.Token).Return(validUser, tc.errUserProfile)
			repoCall := repo.On("Retrieve", context.Background(), "test", mock.Anything).Return(ui.Dashboard{}, tc.errView)
			_, err := svc.ViewDashboard(context.Background(), validSession, "test")
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "UserProfile", validSession.Token)
				repoCall.Parent.AssertCalled(t, "Retrieve", context.Background(), "test", mock.Anything)
			}
			sdkCall.Unset()
			repoCall.Unset()
		})
	}
}

func TestListDashboards(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc           string
		errUserProfile errors.SDKError
		errRetrieve    error
		err            error
	}{
		{
			desc: "success",
		},
		{
			desc:           "sdk error",
			errUserProfile: sdkerr,
			err:            ui.ErrFailedRetrieveUserID,
		},
		{
			desc:        "failed to retrieve dashboard",
			errRetrieve: fmt.Errorf("failed to retrieve dashboard"),
			err:         ui.ErrFailedRetreive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			page := ui.DashboardPageMeta{
				Offset:    0,
				Limit:     10,
				CreatedBy: validUser.ID,
			}
			sdkCall := sdkmock.On("UserProfile", validSession.Token).Return(validUser, tc.errUserProfile)
			repoCall := repo.On("RetrieveAll", context.Background(), page).Return(ui.DashboardPage{}, tc.errRetrieve)
			_, err := svc.ListDashboards(context.Background(), validSession.Token, 1, 10)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "UserProfile", validSession.Token)
				repoCall.Parent.AssertCalled(t, "RetrieveAll", context.Background(), page)
			}
			sdkCall.Unset()
			repoCall.Unset()
		})
	}
}

func TestDashboards(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc string
		prov oauth2.Provider
		err  error
	}{
		{
			desc: "success",
			prov: provider,
			err:  nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			page, err := svc.Dashboards(validSession)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				assert.NotEmpty(t, page, "expected page to be not empty")
			}
		})
	}
}

func TestUpdateDashboard(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc           string
		errUserProfile errors.SDKError
		errUpdate      error
		err            error
	}{
		{
			desc: "success",
		},
		{
			desc:           "sdk error",
			errUserProfile: sdkerr,
			err:            ui.ErrFailedRetrieveUserID,
		},
		{
			desc:      "failed to update dashboard",
			errUpdate: fmt.Errorf("failed to update dashboard"),
			err:       ui.ErrFailedDashboardUpdate,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("UserProfile", validSession.Token).Return(validUser, tc.errUserProfile)
			repoCall := repo.On("Update", context.Background(), "test", validUser.ID, validDashboardReq).Return(tc.errUpdate)
			err := svc.UpdateDashboard(context.Background(), validSession.Token, "test", validDashboardReq)
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "UserProfile", validSession.Token)
				repoCall.Parent.AssertCalled(t, "Update", context.Background(), "test", validUser.ID, validDashboardReq)
			}
			sdkCall.Unset()
			repoCall.Unset()
		})
	}
}

func TestDeleteDashboard(t *testing.T) {
	svc, err := ui.New(sdkmock, repo, idProvider, prefix, provider)
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))

	cases := []struct {
		desc           string
		errUserProfile errors.SDKError
		errDelete      error
		err            error
	}{
		{
			desc: "success",
		},
		{
			desc:           "sdk error",
			errUserProfile: sdkerr,
			err:            ui.ErrFailedRetrieveUserID,
		},
		{
			desc:      "failed to delete dashboard",
			errDelete: fmt.Errorf("failed to delete dashboard"),
			err:       ui.ErrFailedDashboardDelete,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkmock.On("UserProfile", validSession.Token).Return(validUser, tc.errUserProfile)
			repoCall := repo.On("Delete", context.Background(), "test", validUser.ID).Return(tc.errDelete)
			err := svc.DeleteDashboard(context.Background(), validSession.Token, "test")
			assert.True(t, errors.Contains(err, tc.err), fmt.Sprintf("expected error: %s, got: %s", tc.err, err))
			if err == nil {
				sdkCall.Parent.AssertCalled(t, "UserProfile", validSession.Token)
				repoCall.Parent.AssertCalled(t, "Delete", context.Background(), "test", validUser.ID)
			}
			sdkCall.Unset()
			repoCall.Unset()
		})
	}
}

func generateID(t *testing.T) string {
	id, err := idProvider.ID()
	require.Nil(t, err, fmt.Sprintf("unexpected error: %s", err))
	return id
}
