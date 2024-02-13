// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/absmach/magistrala"
	"github.com/absmach/magistrala-ui/ui"
	"github.com/absmach/magistrala/pkg/errors"
	sdk "github.com/absmach/magistrala/pkg/sdk/go"
	"github.com/go-chi/chi/v5"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/go-zoo/bone"
	"github.com/golang-jwt/jwt"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	htmContentType          = "text/html"
	jsonContentType         = "application/json"
	staticDir               = "ui/web/static"
	protocol                = "http"
	pageKey                 = "page"
	limitKey                = "limit"
	itemKey                 = "item"
	nameKey                 = "name"
	refererKey              = "referer_url"
	relationKey             = "relation"
	domainKey               = "domain"
	permissionKey           = "permission"
	identityKey             = "identity"
	statusKey               = "status"
	defPage                 = 1
	defLimit                = 10
	defKey                  = ""
	usersAPIEndpoint        = "/users"
	thingsAPIEndpoint       = "/things"
	channelsAPIEndpoint     = "/channels"
	groupsAPIEndpoint       = "/groups"
	bootstrapAPIEndpoint    = "/bootstraps"
	membersAPIEndpoint      = "/domains/members"
	loginAPIEndpoint        = "/login"
	tokenRefreshAPIEndpoint = "/token/refresh"
	domainsAPIEndpoint      = "/domains"
	errorAPIEndpoint        = "error"
	thingsItem              = "things"
	channelsItem            = "channels"
	groupsItem              = "groups"
	accessTokenKey          = "access_token"
	refreshTokenKey         = "refresh_token"
	sessionDetailsKey       = "session_details"
	channelKey              = "channel"
	thingKey                = "thing"
	loggedInKey             = "logged_in"
)

var (
	clientsHeaderLen = 5
	groupsHeaderLen  = 3
	minRows          = 2
)

type number interface {
	int64 | float64 | uint16 | uint64
}

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(svc ui.Service, r *chi.Mux, instanceID string) http.Handler {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(encodeError),
	}

	r.Get("/register", kithttp.NewServer(
		viewRegistrationEndpoint(svc),
		decodeViewRegistrationRequest,
		encodeResponse,
		opts...,
	).ServeHTTP)

	r.Post("/register", kithttp.NewServer(
		registerUserEndpoint(svc),
		decodeRegisterUserRequest,
		encodeResponse,
		opts...,
	).ServeHTTP)

	r.Get("/login", kithttp.NewServer(
		loginEndpoint(svc),
		decodeLoginRequest,
		encodeResponse,
		opts...,
	).ServeHTTP)

	r.Post("/login", kithttp.NewServer(
		tokenEndpoint(svc),
		decodeTokenRequest,
		encodeResponse,
		opts...,
	).ServeHTTP)

	r.Get("/token/refresh", kithttp.NewServer(
		refreshTokenEndpoint(svc),
		decodeRefreshTokenRequest,
		encodeResponse,
		opts...,
	).ServeHTTP)

	r.Get("/logout", kithttp.NewServer(
		logoutEndpoint(svc),
		decodeLogoutRequest,
		encodeResponse,
		opts...,
	).ServeHTTP)

	r.HandleFunc("/signup/kratos", kratosSignUpHandler(svc))
	r.HandleFunc("/signin/kratos", kratosSignInHandler(svc))

	r.Post("/reset-request", kithttp.NewServer(
		passwordResetRequestEndpoint(svc),
		decodePasswordResetRequest,
		encodeResponse,
		opts...,
	).ServeHTTP)

	r.Get("/error", kithttp.NewServer(
		errorPageEndpoint(svc),
		decodeError,
		encodeResponse,
		opts...,
	).ServeHTTP)

	r.Post("/password/reset", kithttp.NewServer(
		passwordResetEndpoint(svc),
		decodePasswordReset,
		encodeResponse,
		opts...,
	).ServeHTTP)

	r.Get("/password/reset", kithttp.NewServer(
		showPasswordResetEndpoint(svc),
		decodeShowPasswordReset,
		encodeResponse,
		opts...,
	).ServeHTTP)

	r.Post("/domains/login", kithttp.NewServer(
		domainLoginEndpoint(svc),
		decodeDomainLoginRequest,
		encodeResponse,
		opts...,
	).ServeHTTP)
	r.Route("/", func(r chi.Router) {
		r.Use(TokenMiddleware)
		r.Use(AuthnMiddleware)
		r.Get("/", http.HandlerFunc(kithttp.NewServer(
			indexEndpoint(svc),
			decodeIndexRequest,
			encodeResponse,
			opts...,
		).ServeHTTP))
		r.Route("/dashboards", func(r chi.Router) {
			r.Get("/{id}", kithttp.NewServer(
				viewDashboardEndpoint(svc),
				decodeViewDashboardRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)
			r.Post("/", kithttp.NewServer(
				createDashboardEndpoint(svc),
				decodeCreateDashboardRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)
			r.Patch("/", kithttp.NewServer(
				updateDashboardEndpoint(svc),
				decodeUpdateDashboardRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)
			r.Get("/list", kithttp.NewServer(
				listDashboardsEndpoint(svc),
				decodeListDashboardsRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)
			r.Get("/", kithttp.NewServer(
				dashboardsEndpoint(svc),
				decodeDashboardRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)
			r.Delete("/", kithttp.NewServer(
				deleteDashboardEndpoint(svc),
				decodeDeleteDashboardRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)
		})
		r.Get("/entities", kithttp.NewServer(
			getEntitiesEndpoint(svc),
			decodeGetEntitiesRequest,
			encodeResponse,
			opts...,
		).ServeHTTP)

		r.Post("/password", kithttp.NewServer(
			updatePasswordEndpoint(svc),
			decodePasswordUpdate,
			encodeResponse,
			opts...,
		).ServeHTTP)

		r.Get("/password", kithttp.NewServer(
			showUpdatePasswordEndpoint(svc),
			decodeShowPasswordUpdate,
			encodeResponse,
			opts...,
		).ServeHTTP)

		r.Route("/users", func(r chi.Router) {
			r.Use(AdminAuthMiddleware)
			r.Post("/", kithttp.NewServer(
				createUserEndpoint(svc),
				decodeUserCreation,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Get("/", kithttp.NewServer(
				listUsersEndpoint(svc),
				decodeListEntityRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/bulk", kithttp.NewServer(
				createUsersEndpoint(svc),
				decodeUsersCreation,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/enable", kithttp.NewServer(
				enableUserEndpoint(svc),
				decodeUserStatusUpdate,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/disable", kithttp.NewServer(
				disableUserEndpoint(svc),
				decodeUserStatusUpdate,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Get("/{id}", kithttp.NewServer(
				viewUserEndpoint(svc),
				decodeView,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}", kithttp.NewServer(
				updateUserEndpoint(svc),
				decodeUserUpdate,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/tags", kithttp.NewServer(
				updateUserTagsEndpoint(svc),
				decodeUserTagsUpdate,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/identity", kithttp.NewServer(
				updateUserIdentityEndpoint(svc),
				decodeUserIdentityUpdate,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/role", kithttp.NewServer(
				updateUserRoleEndpoint(svc),
				decodeUserRoleUpdate,
				encodeResponse,
				opts...,
			).ServeHTTP)
		})

		r.Route("/things", func(r chi.Router) {
			r.Post("/", kithttp.NewServer(
				createThingEndpoint(svc),
				decodeThingCreation,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/bulk", kithttp.NewServer(
				createThingsEndpoint(svc),
				decodeThingsCreation,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Get("/", kithttp.NewServer(
				listThingsEndpoint(svc),
				decodeListEntityRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/enable", kithttp.NewServer(
				enableThingEndpoint(svc),
				decodeThingStatusUpdate,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/disable", kithttp.NewServer(
				disableThingEndpoint(svc),
				decodeThingStatusUpdate,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Get("/{id}", kithttp.NewServer(
				viewThingEndpoint(svc),
				decodeView,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}", kithttp.NewServer(
				updateThingEndpoint(svc),
				decodeThingUpdate,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/tags", kithttp.NewServer(
				updateThingTagsEndpoint(svc),
				decodeThingTagsUpdate,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/secret", kithttp.NewServer(
				updateThingSecretEndpoint(svc),
				decodeThingSecretUpdate,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Get("/{id}/channels", kithttp.NewServer(
				listChannelsByThingEndpoint(svc),
				decodeListEntityByIDRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/channels/connect", kithttp.NewServer(
				connectChannelEndpoint(svc),
				decodeConnectChannel,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/channels/disconnect", kithttp.NewServer(
				disconnectChannelEndpoint(svc),
				decodeConnectChannel,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/share", kithttp.NewServer(
				shareThingEndpoint(svc),
				decodeShareThingRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/unshare", kithttp.NewServer(
				unshareThingEndpoint(svc),
				decodeShareThingRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Get("/{id}/users", kithttp.NewServer(
				listThingMembersEndpoint(svc),
				decodeListEntityByIDRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)
		})

		r.Route("/channels", func(r chi.Router) {
			r.Post("/", kithttp.NewServer(
				createChannelEndpoint(svc),
				decodeChannelCreation,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/bulk", kithttp.NewServer(
				createChannelsEndpoint(svc),
				decodeChannelsCreation,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Get("/", kithttp.NewServer(
				listChannelsEndpoint(svc),
				decodeListEntityRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/enable", kithttp.NewServer(
				enableChannelEndpoint(svc),
				decodeChannelStatusUpdate,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/disable", kithttp.NewServer(
				disableChannelEndpoint(svc),
				decodeChannelStatusUpdate,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Get("/{id}", kithttp.NewServer(
				viewChannelEndpoint(svc),
				decodeView,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}", kithttp.NewServer(
				updateChannelEndpoint(svc),
				decodeChannelUpdate,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/things/connect", kithttp.NewServer(
				connectChannelEndpoint(svc),
				decodeConnectChannel,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/things/disconnect", kithttp.NewServer(
				disconnectChannelEndpoint(svc),
				decodeConnectChannel,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Get("/{id}/things", kithttp.NewServer(
				listThingsByChannelEndpoint(svc),
				decodeListEntityByIDRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/users/assign", kithttp.NewServer(
				AddMemberToChannelEndpoint(svc),
				decodeAddMemberToChannelRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/users/unassign", kithttp.NewServer(
				RemoveMemberFromChannelEndpoint(svc),
				decodeAddMemberToChannelRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Get("/{id}/users", kithttp.NewServer(
				ListChannelMembersEndpoint(svc),
				decodeListEntityByIDRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/groups/assign", kithttp.NewServer(
				addGroupToChannelEndpoint(svc),
				decodeAddGroupToChannelRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/groups/unassign", kithttp.NewServer(
				removeGroupFromChannelEndpoint(svc),
				decodeAddGroupToChannelRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Get("/{id}/groups", kithttp.NewServer(
				ListChannelGroupsEndpoint(svc),
				decodeListEntityByIDRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)
		})

		r.Route("/groups", func(r chi.Router) {
			r.Post("/", kithttp.NewServer(
				createGroupEndpoint(svc),
				decodeGroupCreation,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/bulk", kithttp.NewServer(
				createGroupsEndpoint(svc),
				decodeGroupsCreation,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Get("/", kithttp.NewServer(
				listGroupsEndpoint(svc),
				decodeListEntityRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/enable", kithttp.NewServer(
				enableGroupEndpoint(svc),
				decodeGroupStatusUpdate,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/disable", kithttp.NewServer(
				disableGroupEndpoint(svc),
				decodeGroupStatusUpdate,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Get("/{id}", kithttp.NewServer(
				viewGroupEndpoint(svc),
				decodeView,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Get("/{id}/users", kithttp.NewServer(
				listGroupMembersEndpoint(svc),
				decodeListEntityByIDRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}", kithttp.NewServer(
				updateGroupEndpoint(svc),
				decodeGroupUpdate,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/users/assign", kithttp.NewServer(
				assignGroupEndpoint(svc),
				decodeAssignGroupRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/users/unassign", kithttp.NewServer(
				unassignGroupEndpoint(svc),
				decodeAssignGroupRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/channels/assign", kithttp.NewServer(
				addGroupToChannelEndpoint(svc),
				decodeAddGroupToChannelRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)
			r.Post("/{id}/channels/unassign", kithttp.NewServer(
				removeGroupFromChannelEndpoint(svc),
				decodeAddGroupToChannelRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Get("/{id}/channels", kithttp.NewServer(
				listGroupChannelsEndpoint(svc),
				decodeListEntityByIDRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)
		})

		r.Route("/messages", func(r chi.Router) {
			r.Post("/", kithttp.NewServer(
				publishMessageEndpoint(svc),
				decodePublishRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Get("/", kithttp.NewServer(
				readMessagesEndpoint(svc),
				decodeReadMessagesRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)
		})

		r.Route("/bootstraps", func(r chi.Router) {
			r.Get("/", kithttp.NewServer(
				listBootstrap(svc),
				decodeListEntityRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/", kithttp.NewServer(
				createBootstrap(svc),
				decodeCreateBootstrapRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Get("/{id}", kithttp.NewServer(
				viewBootstrap(svc),
				decodeView,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}", kithttp.NewServer(
				updateBootstrap(svc),
				decodeUpdateBootstrap,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/delete", kithttp.NewServer(
				deleteBootstrapEndpoint(svc),
				decodeDeleteBootstrap,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/state", kithttp.NewServer(
				updateBootstrapStateEndpoint(svc),
				decodeUpdateBootstrapState,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/certs", kithttp.NewServer(
				updateBootstrapCerts(svc),
				decodeUpdateBootstrapCerts,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/connections", kithttp.NewServer(
				updateBootstrapConnections(svc),
				decodeUpdateBootstrapConnections,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Get("/{id}/terminal", kithttp.NewServer(
				getTerminalEndpoint(svc),
				decodeView,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/{id}/terminal/input", kithttp.NewServer(
				handleTerminalInputEndpoint(svc),
				decodeTerminalCommandRequest,
				encodeJSONResponse,
				opts...,
			).ServeHTTP)
		})

		r.Route("/invitations", func(r chi.Router) {
			r.Post("/", kithttp.NewServer(
				sendInvitationEndpoint(svc),
				decodeSendInvitationRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Get("/", kithttp.NewServer(
				listInvitationsEndpoint(svc),
				decodeListInvitationsRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/accept", kithttp.NewServer(
				acceptInvitationEndpoint(svc),
				decodeAcceptInvitationRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/delete", kithttp.NewServer(
				deleteInvitationEndpoint(svc),
				decodeDeleteInvitationRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)
		})
	})
	r.Route("/domains", func(r chi.Router) {
		r.Use(TokenMiddleware)
		r.Post("/", kithttp.NewServer(
			createDomainEndpoint(svc),
			decodeCreateDomainRequest,
			encodeResponse,
			opts...,
		).ServeHTTP)

		r.Get("/", kithttp.NewServer(
			listDomainsEndpoint(svc),
			decodeListDomainsRequest,
			encodeResponse,
			opts...,
		).ServeHTTP)

		r.Post("/enable", kithttp.NewServer(
			enableDomainEndpoint(svc),
			decodeDomainStatusUpdate,
			encodeResponse,
			opts...,
		).ServeHTTP)

		r.Post("/disable", kithttp.NewServer(
			disableDomainEndpoint(svc),
			decodeDomainStatusUpdate,
			encodeResponse,
			opts...,
		).ServeHTTP)

		r.Get("/{id}", kithttp.NewServer(
			domainEndpoint(svc),
			decodeListEntityByIDRequest,
			encodeResponse,
			opts...,
		).ServeHTTP)

		r.Post("/{id}", kithttp.NewServer(
			updateDomainEndpoint(svc),
			decodeUpdateDomainRequest,
			encodeResponse,
			opts...,
		).ServeHTTP)

		r.Post("/{id}/tags", kithttp.NewServer(
			updateDomainTagsEndpoint(svc),
			decodeUpdateDomainTagsRequest,
			encodeResponse,
			opts...,
		).ServeHTTP)

		r.Post("/{id}/assign", kithttp.NewServer(
			assignMemberEndpoint(svc),
			decodeAssignMemberRequest,
			encodeResponse,
			opts...,
		).ServeHTTP)

		r.Post("/{id}/unassign", kithttp.NewServer(
			unassignMemberEndpoint(svc),
			decodeAssignMemberRequest,
			encodeResponse,
			opts...,
		).ServeHTTP)

		r.Get("/{id}/members", kithttp.NewServer(
			listMembersEndpoint(svc),
			decodeListEntityByIDRequest,
			encodeResponse,
			opts...,
		).ServeHTTP)

		r.Get("/members", kithttp.NewServer(
			viewMemberEndpoint(svc),
			decodeViewMemberRequest,
			encodeResponse,
			opts...,
		).ServeHTTP)
	})

	r.Get("/health", magistrala.Health("ui", instanceID))
	r.Handle("/metrics", promhttp.Handler())

	r.NotFound(kithttp.NewServer(
		errorPageEndpoint(svc),
		decodePageNotFound,
		encodeResponse,
		opts...,
	).ServeHTTP)

	handleStaticFiles(r)

	return r
}

func decodeIndexRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	req := indexReq{
		token: token,
	}

	return req, nil
}

func decodeViewRegistrationRequest(_ context.Context, _ *http.Request) (interface{}, error) {
	return nil, nil
}

func decodeCreateDashboardRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	var data createDashboardReq
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return nil, err
	}

	req := createDashboardReq{
		token:       token,
		Name:        data.Name,
		Description: data.Description,
	}

	return req, nil
}

func decodeListDashboardsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}
	page, err := readNumQuery[uint64](r, pageKey, defPage)
	if err != nil {
		return nil, err
	}

	limit, err := readNumQuery[uint64](r, limitKey, defLimit)
	if err != nil {
		return nil, err
	}
	req := listDashboardsReq{
		token: token,
		page:  page,
		limit: limit,
	}

	return req, nil
}

func decodeDashboardRequest(_ context.Context, _ *http.Request) (interface{}, error) {
	return nil, nil
}

func decodeUpdateDashboardRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}
	var data updateDashboardReq
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return nil, err
	}
	req := updateDashboardReq{
		token:       token,
		ID:          data.ID,
		Name:        data.Name,
		Description: data.Description,
		Metadata:    data.Metadata,
		Layout:      data.Layout,
	}

	return req, nil
}

func decodeDeleteDashboardRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}
	var data deleteDashboardReq
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return nil, err
	}
	req := deleteDashboardReq{
		token: token,
		ID:    data.ID,
	}

	return req, nil
}

func decodeViewDashboardRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	req := viewDashboardReq{
		token:       token,
		DashboardID: chi.URLParam(r, "id"),
	}

	return req, nil
}

func decodeLoginRequest(_ context.Context, _ *http.Request) (interface{}, error) {
	return nil, nil
}

func decodeShowPasswordUpdate(_ context.Context, _ *http.Request) (interface{}, error) {
	return nil, nil
}

func decodePasswordUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}
	req := updateUserPasswordReq{
		token:   token,
		oldPass: r.PostFormValue("oldpass"),
		newPass: r.PostFormValue("newpass"),
	}

	return req, nil
}

func decodePasswordResetRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := passwordResetRequestReq{
		email: r.PostFormValue("email"),
	}
	return req, nil
}

func decodePasswordReset(_ context.Context, r *http.Request) (interface{}, error) {
	accessToken, err := readStringQuery(r, accessTokenKey, defKey)
	if err != nil {
		return nil, err
	}

	req := passwordResetReq{
		token:           accessToken,
		password:        r.PostFormValue("password"),
		confirmPassword: r.PostFormValue("confirmPassword"),
	}
	return req, nil
}

func decodeShowPasswordReset(_ context.Context, _ *http.Request) (interface{}, error) {
	return nil, nil
}

func decodeRegisterUserRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := registerUserReq{
		User: sdk.User{
			Name: r.PostFormValue("name"),
			Credentials: sdk.Credentials{
				Identity: r.PostFormValue("email"),
				Secret:   r.PostFormValue("password"),
			},
		},
	}

	return req, nil
}

func decodeTokenRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := tokenReq{
		sdk.Login{
			Identity: r.PostFormValue("email"),
			Secret:   r.PostFormValue("password"),
		},
	}

	return req, nil
}

func decodeRefreshTokenRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, refreshTokenKey)
	if err != nil {
		return nil, err
	}

	referer, err := readStringQuery(r, refererKey, defKey)
	if err != nil {
		return nil, err
	}

	req := refreshTokenReq{
		refreshToken: token,
		ref:          referer,
	}

	return req, nil
}

func decodeLogoutRequest(_ context.Context, _ *http.Request) (interface{}, error) {
	return nil, nil
}

func kratosSignInHandler(svc ui.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		url, err := svc.KratosSignIn()
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return
		}

		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

func kratosSignUpHandler(svc ui.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		url, err := svc.KratosSignUp()
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return
		}

		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

func decodeUserCreation(_ context.Context, r *http.Request) (interface{}, error) {
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(r.PostFormValue("metadata")), &meta); err != nil {
		return nil, err
	}
	var tags []string
	if err := json.Unmarshal([]byte(r.PostFormValue("tags")), &tags); err != nil {
		return nil, err
	}
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}
	credentials := sdk.Credentials{
		Identity: r.PostFormValue("identity"),
		Secret:   r.PostFormValue("secret"),
	}
	user := sdk.User{
		Name:        r.PostFormValue("name"),
		Credentials: credentials,
		Tags:        tags,
		Metadata:    meta,
	}

	req := createUserReq{
		token: token,
		User:  user,
	}

	return req, nil
}

func decodeUsersCreation(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	file, handler, err := r.FormFile("usersFile")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if !strings.HasSuffix(handler.Filename, ".csv") {
		return nil, errInvalidFile
	}
	reader := csv.NewReader(file)

	rows, err := reader.ReadAll()
	if err != nil {
		return nil, errFileFormat
	}

	if len(rows) < minRows {
		return nil, errFileFormat
	}

	if len(rows[0]) != clientsHeaderLen {
		return nil, errFileFormat
	}

	users := []sdk.User{}

	for _, row := range rows[1:] {
		var user sdk.User

		if row[1] == "" && row[2] == "" {
			return nil, errFileFormat
		}
		user.Credentials.Identity = row[1]
		user.Credentials.Secret = row[2]

		if row[0] != "" {
			user.Name = row[0]
		}

		if row[3] != "" {
			if err := json.Unmarshal([]byte(row[3]), &user.Metadata); err != nil {
				return nil, errFileFormat
			}
		}

		if row[4] != "" {
			if err := json.Unmarshal([]byte(row[4]), &user.Tags); err != nil {
				return nil, errFileFormat
			}
		}

		users = append(users, user)
	}
	req := createUsersReq{
		token: token,
		users: users,
	}

	return req, nil
}

func decodeView(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}
	req := viewResourceReq{
		token: token,
		id:    chi.URLParam(r, "id"),
	}

	return req, nil
}

func decodeUserUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	var user sdk.User
	if err = json.NewDecoder(r.Body).Decode(&user); err != nil {
		return nil, err
	}
	user.ID = chi.URLParam(r, "id")

	req := updateUserReq{
		token: token,
		User:  user,
	}

	return req, nil
}

func decodeUserTagsUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	var user sdk.User
	if err = json.NewDecoder(r.Body).Decode(&user); err != nil {
		return nil, err
	}
	user.ID = chi.URLParam(r, "id")

	req := updateUserTagsReq{
		token: token,
		User:  user,
	}

	return req, nil
}

func decodeUserIdentityUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	var credentials sdk.Credentials
	if err = json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		return nil, err
	}

	req := updateUserIdentityReq{
		token: token,
		User: sdk.User{
			ID:          chi.URLParam(r, "id"),
			Credentials: credentials,
		},
	}

	return req, nil
}

func decodeUserStatusUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	req := updateUserStatusReq{
		token: token,
		id:    r.PostFormValue("entityID"),
	}

	return req, nil
}

func decodeUserRoleUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	req := updateUserRoleReq{
		token: token,
		User: sdk.User{
			ID:   chi.URLParam(r, "id"),
			Role: r.PostFormValue("role"),
		},
	}

	return req, nil
}

func decodeAssignGroupRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	return assignReq{
		token:   token,
		groupID: chi.URLParam(r, "id"),
		UsersRelationRequest: sdk.UsersRelationRequest{
			UserIDs:  r.Form["userID"],
			Relation: r.Form.Get("relation"),
		},
	}, nil
}

func decodeShareThingRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	return shareThingReq{
		token: token,
		id:    chi.URLParam(r, "id"),
		UsersRelationRequest: sdk.UsersRelationRequest{
			UserIDs:  r.Form["userID"],
			Relation: r.Form.Get("relation"),
		},
	}, nil
}

func decodeAddMemberToChannelRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	return addUserToChannelReq{
		token:     token,
		ChannelID: chi.URLParam(r, "id"),
		UsersRelationRequest: sdk.UsersRelationRequest{
			Relation: r.Form.Get("relation"),
			UserIDs:  r.Form["userID"],
		},
	}, nil
}

func decodeThingCreation(_ context.Context, r *http.Request) (interface{}, error) {
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(r.PostFormValue("metadata")), &meta); err != nil {
		return nil, err
	}
	var tags []string
	if err := json.Unmarshal([]byte(r.PostFormValue("tags")), &tags); err != nil {
		return nil, err
	}
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	req := createThingReq{
		token: token,
		Thing: sdk.Thing{
			Name: r.PostFormValue("name"),
			ID:   r.PostFormValue("thingID"),
			Credentials: sdk.Credentials{
				Identity: r.PostFormValue("identity"),
				Secret:   r.PostFormValue("secret"),
			},
			Tags:     tags,
			Metadata: meta,
		},
	}

	return req, nil
}

func decodeThingUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	var thing sdk.Thing
	if err = json.NewDecoder(r.Body).Decode(&thing); err != nil {
		return nil, err
	}
	thing.ID = chi.URLParam(r, "id")

	req := updateThingReq{
		token: token,
		Thing: thing,
	}

	return req, nil
}

func decodeThingTagsUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	var thing sdk.Thing
	if err = json.NewDecoder(r.Body).Decode(&thing); err != nil {
		return nil, err
	}
	thing.ID = chi.URLParam(r, "id")

	req := updateThingTagsReq{
		token: token,
		Thing: thing,
	}

	return req, nil
}

func decodeThingSecretUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	var credentials sdk.Credentials
	if err = json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		return nil, err
	}

	req := updateThingSecretReq{
		token: token,
		Thing: sdk.Thing{
			ID:          chi.URLParam(r, "id"),
			Credentials: credentials,
		},
	}

	return req, nil
}

func decodeThingStatusUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	req := updateThingStatusReq{
		token: token,
		id:    r.PostFormValue("entityID"),
	}

	return req, nil
}

func decodeThingsCreation(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	file, handler, err := r.FormFile("thingsFile")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if !strings.HasSuffix(handler.Filename, ".csv") {
		return nil, errInvalidFile
	}
	reader := csv.NewReader(file)

	rows, err := reader.ReadAll()
	if err != nil {
		return nil, errFileFormat
	}

	if len(rows) < minRows {
		return nil, errFileFormat
	}

	if len(rows[0]) != clientsHeaderLen {
		return nil, errFileFormat
	}

	things := []sdk.Thing{}

	for _, row := range rows[1:] {
		if row[0] == "" && row[1] == "" && row[2] == "" && row[3] == "" && row[4] == "" {
			continue
		}
		var thing sdk.Thing
		if row[0] != "" {
			thing.Name = row[0]
		}

		if row[1] != "" {
			thing.Credentials.Identity = row[1]
		}

		if row[2] != "" {
			thing.Credentials.Secret = row[2]
		}

		if row[3] != "" {
			if err := json.Unmarshal([]byte(row[3]), &thing.Tags); err != nil {
				return nil, errFileFormat
			}
		}

		if row[4] != "" {
			if err := json.Unmarshal([]byte(row[4]), &thing.Metadata); err != nil {
				return nil, errFileFormat
			}
		}

		things = append(things, thing)
	}
	req := createThingsReq{
		token:  token,
		things: things,
	}

	return req, nil
}

func decodeChannelCreation(_ context.Context, r *http.Request) (interface{}, error) {
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(r.PostFormValue("metadata")), &meta); err != nil {
		return nil, err
	}

	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	ch := sdk.Channel{
		Name:        r.PostFormValue("name"),
		Description: r.PostFormValue("description"),
		Metadata:    meta,
		ParentID:    r.PostFormValue("parentID"),
	}

	req := createChannelReq{
		token:   token,
		Channel: ch,
	}

	return req, nil
}

func decodeChannelsCreation(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	file, handler, err := r.FormFile("channelsFile")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if !strings.HasSuffix(handler.Filename, ".csv") {
		return nil, errInvalidFile
	}
	reader := csv.NewReader(file)

	rows, err := reader.ReadAll()
	if err != nil {
		return nil, errInvalidFile
	}

	if len(rows) < minRows {
		return nil, errFileFormat
	}

	if len(rows[0]) != groupsHeaderLen {
		return nil, errFileFormat
	}

	channels := []sdk.Channel{}

	for _, row := range rows[1:] {
		var channel sdk.Channel
		if row[0] == "" {
			return nil, errFileFormat
		}
		channel.Name = row[0]

		if row[1] != "" {
			if err := json.Unmarshal([]byte(row[1]), &channel.Metadata); err != nil {
				return nil, errFileFormat
			}
		}

		if row[2] != "" {
			channel.Description = row[2]
		}

		channels = append(channels, channel)
	}
	req := createChannelsReq{
		token:    token,
		Channels: channels,
	}

	return req, nil
}

func decodeChannelUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	var channel sdk.Channel
	if err = json.NewDecoder(r.Body).Decode(&channel); err != nil {
		return nil, err
	}
	channel.ID = chi.URLParam(r, "id")

	req := updateChannelReq{
		token:   token,
		Channel: channel,
	}

	return req, nil
}

func decodeConnectChannel(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	item, err := readStringQuery(r, itemKey, defKey)
	if err != nil {
		return nil, err
	}

	var req connectThingReq

	switch item {
	case thingsItem:
		req = connectThingReq{
			token:     token,
			channelID: r.Form.Get("channelID"),
			thingID:   chi.URLParam(r, "id"),
			item:      item,
		}
	case channelsItem:
		req = connectThingReq{
			token:     token,
			channelID: chi.URLParam(r, "id"),
			thingID:   r.Form.Get("thingID"),
			item:      item,
		}
	}

	return req, nil
}

func decodeChannelStatusUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	req := updateChannelStatusReq{
		token: token,
		id:    r.PostFormValue("entityID"),
	}

	return req, nil
}

func decodeAddGroupToChannelRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	item, err := readStringQuery(r, itemKey, defKey)
	if err != nil {
		return nil, err
	}

	req := addUserGroupToChannelReq{
		token: token,
		item:  item,
	}

	switch item {
	case channelsItem:
		req.channelID = chi.URLParam(r, "id")
		req.UserGroupIDs = r.Form["groupID"]
	case groupsItem:
		req.UserGroupIDs = []string{chi.URLParam(r, "id")}
		req.channelID = r.Form.Get("channelID")
	}

	return req, nil
}

func decodeGroupCreation(_ context.Context, r *http.Request) (interface{}, error) {
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(r.PostFormValue("metadata")), &meta); err != nil {
		return nil, err
	}
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	req := createGroupReq{
		token: token,
		Group: sdk.Group{
			Name:        r.PostFormValue("name"),
			Description: r.PostFormValue("description"),
			Metadata:    meta,
			ParentID:    r.PostFormValue("parentID"),
		},
	}

	return req, nil
}

func decodeGroupsCreation(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	file, handler, err := r.FormFile("groupsFile")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if !strings.HasSuffix(handler.Filename, ".csv") {
		return nil, errInvalidFile
	}
	reader := csv.NewReader(file)

	rows, err := reader.ReadAll()
	if err != nil {
		return nil, errInvalidFile
	}

	if len(rows) < minRows {
		return nil, errFileFormat
	}

	if len(rows[0]) != groupsHeaderLen {
		return nil, errFileFormat
	}

	groups := []sdk.Group{}

	for _, row := range rows[1:] {
		var group sdk.Group
		if row[0] == "" {
			return nil, errFileFormat
		}
		group.Name = row[0]

		if row[1] != "" {
			if err := json.Unmarshal([]byte(row[1]), &group.Metadata); err != nil {
				return nil, errFileFormat
			}
		}

		if row[2] != "" {
			group.Description = row[2]
		}

		groups = append(groups, group)
	}
	req := createGroupsReq{
		token:  token,
		Groups: groups,
	}

	return req, nil
}

func decodeGroupUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	var group sdk.Group
	if err = json.NewDecoder(r.Body).Decode(&group); err != nil {
		return nil, err
	}
	group.ID = chi.URLParam(r, "id")

	req := updateGroupReq{
		token: token,
		Group: group,
	}

	return req, nil
}

func decodeGroupStatusUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	req := updateGroupStatusReq{
		token: token,
		id:    r.PostFormValue("entityID"),
	}

	return req, nil
}

func decodePublishRequest(_ context.Context, r *http.Request) (interface{}, error) {
	floatValue, err := strconv.ParseFloat(r.PostFormValue("value"), 64)
	if err != nil {
		return nil, err
	}

	req := publishReq{
		thingKey:  r.PostFormValue("thingKey"),
		channelID: r.PostFormValue("channelID"),
		Message: ui.Message{
			BaseTime: float64(time.Now().Unix()),
			BaseUnit: r.PostFormValue("unit"),
			Name:     r.PostFormValue("name"),
			Unit:     r.PostFormValue("unit"),
			Value:    floatValue,
		},
	}

	return req, nil
}

func decodeReadMessagesRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	page, err := readNumQuery[uint64](r, pageKey, defPage)
	if err != nil {
		return nil, err
	}

	limit, err := readNumQuery[uint64](r, limitKey, defLimit)
	if err != nil {
		return nil, err
	}

	req := readMessagesReq{
		token:     token,
		channelID: r.Form.Get("channel"),
		thingKey:  r.Form.Get("thing"),
		page:      page,
		limit:     limit,
	}

	return req, nil
}

func decodeTerminalCommandRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}
	req := bootstrapCommandReq{
		token:   token,
		id:      chi.URLParam(r, "id"),
		command: strings.ReplaceAll(strings.Trim(r.PostFormValue("command"), " "), " ", ","),
	}
	return req, nil
}

func decodeCreateBootstrapRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	req := createBootstrapReq{
		token: token,
		BootstrapConfig: sdk.BootstrapConfig{
			ThingID:     r.FormValue("thingID"),
			ExternalID:  r.FormValue("externalID"),
			ExternalKey: r.FormValue("externalKey"),
			Channels:    r.PostForm["channelID"],
			Name:        r.FormValue("name"),
			Content:     r.FormValue("content"),
			ClientCert:  r.FormValue("clientCert"),
			ClientKey:   r.FormValue("clientKey"),
			CACert:      r.FormValue("CACert"),
			State:       1,
		},
	}

	return req, nil
}

func decodeUpdateBootstrap(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	var config sdk.BootstrapConfig
	if err = json.NewDecoder(r.Body).Decode(&config); err != nil {
		return nil, err
	}
	config.ThingID = chi.URLParam(r, "id")

	req := updateBootstrapReq{
		token:           token,
		BootstrapConfig: config,
	}

	return req, nil
}

func decodeDeleteBootstrap(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	req := deleteBootstrapReq{
		token: token,
		id:    chi.URLParam(r, "id"),
	}

	return req, nil
}

func decodeUpdateBootstrapState(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	state, err := strconv.Atoi(r.FormValue("state"))
	if err != nil {
		return nil, err
	}

	req := updateBootstrapStateReq{
		token: token,
		BootstrapConfig: sdk.BootstrapConfig{
			ThingID: chi.URLParam(r, "id"),
			State:   state,
		},
	}

	return req, nil
}

func decodeUpdateBootstrapCerts(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	var config sdk.BootstrapConfig
	if err = json.NewDecoder(r.Body).Decode(&config); err != nil {
		return nil, err
	}
	config.ThingID = chi.URLParam(r, "id")

	req := updateBootstrapCertReq{
		token:           token,
		BootstrapConfig: config,
	}

	return req, nil
}

func decodeUpdateBootstrapConnections(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	req := updateBootstrapConnReq{
		token: token,
		BootstrapConfig: sdk.BootstrapConfig{
			ThingID:  chi.URLParam(r, "id"),
			Channels: r.PostForm["channelID"],
		},
	}

	return req, nil
}

func decodeListEntityRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}
	page, err := readNumQuery[uint64](r, pageKey, defPage)
	if err != nil {
		return nil, err
	}

	limit, err := readNumQuery[uint64](r, limitKey, defLimit)
	if err != nil {
		return nil, err
	}

	status, err := readStringQuery(r, statusKey, defKey)
	if err != nil {
		return nil, err
	}

	req := listEntityReq{
		token:  token,
		status: status,
		page:   page,
		limit:  limit,
	}

	return req, nil
}

func decodeListEntityByIDRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}
	page, err := readNumQuery[uint64](r, pageKey, defPage)
	if err != nil {
		return nil, err
	}

	limit, err := readNumQuery[uint64](r, limitKey, defLimit)
	if err != nil {
		return nil, err
	}

	relation, err := readStringQuery(r, relationKey, defKey)
	if err != nil {
		return nil, err
	}

	req := listEntityByIDReq{
		token:    token,
		id:       chi.URLParam(r, "id"),
		page:     page,
		limit:    limit,
		relation: relation,
	}

	return req, nil
}

func decodeGetEntitiesRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	item, err := readStringQuery(r, itemKey, defKey)
	if err != nil {
		return nil, err
	}
	name, err := readStringQuery(r, nameKey, defKey)
	if err != nil {
		return nil, err
	}

	domainID, err := readStringQuery(r, domainKey, defKey)
	if err != nil {
		return nil, err
	}

	permission, err := readStringQuery(r, permissionKey, defKey)
	if err != nil {
		return nil, err
	}

	page, err := readNumQuery[uint64](r, pageKey, defPage)
	if err != nil {
		return nil, err
	}

	limit, err := readNumQuery[uint64](r, limitKey, defLimit)
	if err != nil {
		return nil, err
	}

	req := getEntitiesReq{
		token:      token,
		item:       item,
		page:       page,
		name:       name,
		domainID:   domainID,
		limit:      limit,
		permission: permission,
	}

	return req, nil
}

func decodeDomainLoginRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, refreshTokenKey)
	if err != nil {
		return nil, err
	}

	req := domainLoginReq{
		token: token,
		Login: sdk.Login{
			DomainID: r.FormValue("domainID"),
		},
	}

	return req, nil
}

func decodeListDomainsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	accessToken, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	refreshToken, err := tokenFromCookie(r, refreshTokenKey)
	if err != nil {
		return nil, err
	}

	page, err := readNumQuery[uint64](r, pageKey, defPage)
	if err != nil {
		return nil, err
	}

	limit, err := readNumQuery[uint64](r, limitKey, defLimit)
	if err != nil {
		return nil, err
	}

	status, err := readStringQuery(r, statusKey, defKey)
	if err != nil {
		return nil, err
	}

	req := listDomainsReq{
		Token: sdk.Token{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
		status: status,
		page:   page,
		limit:  limit,
	}

	return req, nil
}

func decodeCreateDomainRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	meta, err := parseMetadata(r)
	if err != nil {
		return nil, err
	}

	tags, err := parseTags(r)
	if err != nil {
		return nil, err
	}

	req := createDomainReq{
		token: token,
		Domain: sdk.Domain{
			Name:     r.FormValue("name"),
			Alias:    r.FormValue("alias"),
			Tags:     tags,
			Metadata: meta,
		},
	}

	return req, nil
}

func decodeUpdateDomainRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	var domain sdk.Domain
	if err = json.NewDecoder(r.Body).Decode(&domain); err != nil {
		return nil, err
	}
	domain.ID = chi.URLParam(r, "id")

	req := updateDomainReq{
		token:  token,
		Domain: domain,
	}

	return req, nil
}

func decodeUpdateDomainTagsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	var domain sdk.Domain
	if err = json.NewDecoder(r.Body).Decode(&domain); err != nil {
		return nil, err
	}
	domain.ID = chi.URLParam(r, "id")

	req := updateDomainTagsReq{
		token:  token,
		Domain: domain,
	}

	return req, nil
}

func decodeDomainStatusUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	req := updateDomainStatusReq{
		token: token,
		id:    r.PostFormValue("entityID"),
	}

	return req, nil
}

func decodeAssignMemberRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	req := assignMemberReq{
		token:    token,
		domainID: chi.URLParam(r, "id"),
		UsersRelationRequest: sdk.UsersRelationRequest{
			UserIDs:  r.Form["userID"],
			Relation: r.Form.Get("relation"),
		},
	}

	return req, nil
}

func decodeViewMemberRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	identity, err := readStringQuery(r, identityKey, defKey)
	if err != nil {
		return nil, err
	}

	req := viewMemberReq{
		token:        token,
		userIdentity: identity,
	}

	return req, nil
}

func decodeSendInvitationRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	req := sendInvitationReq{
		token: token,
		Invitation: sdk.Invitation{
			DomainID: r.PostFormValue("domainID"),
			UserID:   r.PostFormValue("userID"),
			Relation: r.PostFormValue("relation"),
		},
	}

	return req, nil
}

func decodeListInvitationsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	page, err := readNumQuery[uint64](r, pageKey, defPage)
	if err != nil {
		return nil, err
	}

	limit, err := readNumQuery[uint64](r, limitKey, defLimit)
	if err != nil {
		return nil, err
	}

	domainID, err := readStringQuery(r, domainKey, defKey)
	if err != nil {
		return nil, err
	}

	req := listInvitationsReq{
		token:    token,
		domainID: domainID,
		page:     page,
		limit:    limit,
	}

	return req, nil
}

func decodeAcceptInvitationRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	req := acceptInvitationReq{
		token:    token,
		domainID: r.Form.Get("domainID"),
	}

	return req, nil
}

func decodeDeleteInvitationRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}

	domain, err := readStringQuery(r, domainKey, defKey)
	if err != nil {
		return nil, err
	}

	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	req := deleteInvitationReq{
		token:    token,
		domain:   domain,
		domainID: r.Form.Get("domainID"),
		userID:   r.Form.Get("userID"),
	}

	return req, nil
}

func decodeError(_ context.Context, r *http.Request) (interface{}, error) {
	errValue, err := readStringQuery(r, "error", "")
	if err != nil {
		return nil, err
	}
	return errorReq{
		err: errValue,
	}, nil
}

func decodePageNotFound(_ context.Context, _ *http.Request) (interface{}, error) {
	return errorReq{
		err: "Whoops! Page not found",
	}, nil
}

func readStringQuery(r *http.Request, key string, def string) (string, error) {
	vals := bone.GetQuery(r, key)
	if len(vals) > 1 {
		return "", errInvalidQueryParams
	}

	if len(vals) == 0 {
		return def, nil
	}

	return vals[0], nil
}

func readNumQuery[N number](r *http.Request, key string, def N) (N, error) {
	vals := bone.GetQuery(r, key)
	if len(vals) > 1 {
		return 0, errInvalidQueryParams
	}
	if len(vals) == 0 {
		return def, nil
	}
	val := vals[0]

	switch any(def).(type) {
	case int64:
		v, err := strconv.ParseInt(val, 10, 64)
		return N(v), err
	case uint64:
		v, err := strconv.ParseUint(val, 10, 64)
		return N(v), err
	case uint16:
		v, err := strconv.ParseUint(val, 10, 16)
		return N(v), err
	case float64:
		v, err := strconv.ParseFloat(val, 64)
		return N(v), err
	default:
		return def, nil
	}
}

func tokenFromCookie(r *http.Request, cookie string) (string, error) {
	c, err := r.Cookie(cookie)
	if err != nil {
		return "", errors.Wrap(err, errAuthorization)
	}

	return c.Value, nil
}

func AdminAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		defer func() {
			if err != nil {
				http.Redirect(w, r, fmt.Sprintf("/%s?error=%s", errorAPIEndpoint, url.QueryEscape(err.Error())), http.StatusSeeOther)
			}
		}()
		tokenString, err := tokenFromCookie(r, sessionDetailsKey)
		if err != nil {
			return
		}

		decodedSession, err := base64.StdEncoding.DecodeString(tokenString)
		if err != nil {
			return
		}

		var session ui.SessionDetails
		if err = json.Unmarshal(decodedSession, &session); err != nil {
			return
		}

		if session.User.Role != "admin" {
			err = errors.ErrAuthorization
			return
		}

		next.ServeHTTP(w, r)
	})
}

func TokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := tokenFromCookie(r, accessTokenKey)
		if err != nil {
			if errors.Contains(err, http.ErrNoCookie) {
				http.Redirect(w, r, "/token/refresh?referer_url="+url.QueryEscape(r.URL.String()), http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Parse the token without validation to get the expiration time
		token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("/%s?error=%s", errorAPIEndpoint, url.QueryEscape(err.Error())), http.StatusSeeOther)
			return
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
				http.Redirect(w, r, "/token/refresh?referer_url="+url.QueryEscape(r.URL.String()), http.StatusSeeOther)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func AuthnMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := tokenFromCookie(r, accessTokenKey)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
		if err != nil {
			http.Redirect(w, r, fmt.Sprintf("/%s?error=%s", errorAPIEndpoint, url.QueryEscape(err.Error())), http.StatusSeeOther)
			return
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			if _, ok := claims["domain"]; !ok {
				http.Redirect(w, r, "/domains", http.StatusSeeOther)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func handleStaticFiles(m *chi.Mux) {
	file, err := os.Open(staticDir)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	infos, err := file.ReadDir(0)
	if err != nil {
		panic(err)
	}
	fs := http.FileServer(http.Dir(staticDir))
	for _, info := range infos {
		if info.IsDir() {
			m.Handle(fmt.Sprintf("/%s/*", info.Name()), fs)
		}
	}
}

func parseMetadata(r *http.Request) (map[string]interface{}, error) {
	metadataStr := r.PostFormValue("metadata")

	metadata := make(map[string]interface{})
	if len(metadataStr) > 0 {
		if err := json.Unmarshal([]byte(metadataStr), &metadata); err != nil {
			return nil, err
		}
	}

	return metadata, nil
}

func parseTags(r *http.Request) ([]string, error) {
	tagsStr := r.PostFormValue("tags")

	tags := make([]string, 0)
	if len(tagsStr) > 0 {
		if err := json.Unmarshal([]byte(tagsStr), &tags); err != nil {
			return nil, err
		}
	}

	return tags, nil
}

func encodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	w.Header().Set("Content-Type", htmContentType)
	ar, _ := response.(uiRes)
	for k, v := range ar.Headers() {
		w.Header().Set(k, v)
	}

	// Add cookies to the response header
	for _, cookie := range ar.Cookies() {
		http.SetCookie(w, cookie)
	}

	w.WriteHeader(ar.Code())

	if ar.Empty() {
		return nil
	}

	if _, err := w.Write(ar.html); err != nil {
		return err
	}

	return nil
}

func encodeJSONResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	if ar, ok := response.(magistrala.Response); ok {
		for k, v := range ar.Headers() {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", jsonContentType)
		w.WriteHeader(ar.Code())

		if ar.Empty() {
			return nil
		}
	}

	return json.NewEncoder(w).Encode(response)
}

func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	_, displayError := errors.Unwrap(err)

	switch {
	case errors.Contains(err, errAuthorization),
		errors.Contains(err, errAuthentication),
		errors.Contains(err, ui.ErrTokenRefresh):
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusSeeOther)
	case errors.Contains(err, ui.ErrToken):
		w.WriteHeader(http.StatusUnauthorized)
	case errors.Contains(err, ui.ErrConflict):
		w.Header().Set("X-Error-Message", err.Error())
		w.WriteHeader(http.StatusConflict)
	case errors.Contains(err, errInvalidFile):
		w.Header().Set("X-Error-Message", err.Error())
		w.WriteHeader(http.StatusUnsupportedMediaType)
	case errors.Contains(err, errFileFormat):
		w.Header().Set("X-Error-Message", err.Error())
		w.WriteHeader(http.StatusBadRequest)
	case errors.Contains(err, ui.ErrFailedCreate),
		errors.Contains(err, ui.ErrFailedRetreive),
		errors.Contains(err, ui.ErrFailedUpdate),
		errors.Contains(err, ui.ErrFailedEnable),
		errors.Contains(err, ui.ErrFailedDisable),
		errors.Contains(err, ui.ErrFailedAssign),
		errors.Contains(err, ui.ErrFailedUnassign),
		errors.Contains(err, ui.ErrFailedConnect),
		errors.Contains(err, ui.ErrFailedDisconnect),
		errors.Contains(err, ui.ErrFailedCreatePolicy),
		errors.Contains(err, ui.ErrFailedUpdatePolicy),
		errors.Contains(err, ui.ErrFailedDeletePolicy),
		errors.Contains(err, ui.ErrFailedReset),
		errors.Contains(err, ui.ErrFailedResetRequest),
		errors.Contains(err, ui.ErrFailedPublish),
		errors.Contains(err, ui.ErrExecTemplate),
		errors.Contains(err, ui.ErrFailedDelete),
		errors.Contains(err, ui.ErrFailedShare),
		errors.Contains(err, ui.ErrFailedUnshare),
		errors.Contains(err, ui.ErrFailedDashboardSave),
		errors.Contains(err, ui.ErrFailedDashboardDelete),
		errors.Contains(err, ui.ErrFailedDashboardUpdate),
		errors.Contains(err, ui.ErrFailedDashboardRetrieve),
		errors.Contains(err, ui.ErrSessionType):
		w.Header().Set("Location", fmt.Sprintf("/%s?error=%s", errorAPIEndpoint, url.QueryEscape(displayError.Error())))
		w.WriteHeader(http.StatusSeeOther)
	default:
		if e, ok := status.FromError(err); ok {
			switch e.Code() {
			case codes.PermissionDenied:
				w.WriteHeader(http.StatusForbidden)
			default:
				w.WriteHeader(http.StatusServiceUnavailable)
			}
			return
		}
		switch err {
		case errMissingSecret,
			errMissingIdentity,
			errLimitSize,
			errPageSize,
			errMissingConfigID,
			errMissingMetadata,
			errMissingEmail,
			errMissingName,
			errMissingChannel,
			errMissingPayload,
			errMissingPassword,
			errMissingError,
			errMissingRefreshToken,
			errMissingRef,
			errMissingConfirmPassword,
			errNameSize,
			errBearerKey,
			errMissingItem,
			errMissingThingID,
			errMissingChannelID,
			errMissingDomainID,
			errMissingUserID,
			errMissingRelation,
			errMissingGroupID,
			errMissingParentID,
			errMissingDescription,
			errMissingThingKey,
			errMissingExternalID,
			errMissingRole,
			errMissingValue,
			errMissingExternalKey:
			w.Header().Set("X-Error-Message", err.Error())
			w.WriteHeader(http.StatusBadRequest)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}
}
