// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
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
	"github.com/absmach/magistrala/pkg/messaging"
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
	thingsItem              = "things"
	channelsItem            = "channels"
	groupsItem              = "groups"
	accessTokenKey          = "token"
	refreshTokenKey         = "refresh_token"
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
		r.Get("/", http.HandlerFunc(kithttp.NewServer(
			indexEndpoint(svc),
			decodeIndexRequest,
			encodeResponse,
			opts...,
		).ServeHTTP))

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

			r.Post("/enabled", kithttp.NewServer(
				enableUserEndpoint(svc),
				decodeUserStatusUpdate,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/disabled", kithttp.NewServer(
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

			r.Post("/enabled", kithttp.NewServer(
				enableThingEndpoint(svc),
				decodeThingStatusUpdate,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/disabled", kithttp.NewServer(
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

			r.Post("/enabled", kithttp.NewServer(
				enableChannelEndpoint(svc),
				decodeChannelStatusUpdate,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/disabled", kithttp.NewServer(
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

			r.Post("/enabled", kithttp.NewServer(
				enableGroupEndpoint(svc),
				decodeGroupStatusUpdate,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Post("/disabled", kithttp.NewServer(
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

			r.Get("/read", kithttp.NewServer(
				readMessageEndpoint(svc),
				decodeReadMessageRequest,
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
		r.Route("/domains", func(r chi.Router) {
			r.Post("/", kithttp.NewServer(
				createDomainEndpoint(svc),
				decodeCreateDomainRequest,
				encodeResponse,
				opts...,
			).ServeHTTP)

			r.Get("/", kithttp.NewServer(
				listDomainsEndpoint(svc),
				decodeListEntityRequest,
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
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := indexReq{
		token: token,
	}

	return req, nil
}

func decodeLoginRequest(_ context.Context, _ *http.Request) (interface{}, error) {
	return nil, nil
}

func decodeShowPasswordUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := showUpdatePasswordReq{
		token: token,
	}

	return req, nil
}

func decodePasswordUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}
	req := updateUserPasswordReq{
		token:   token,
		OldPass: r.PostFormValue("oldpass"),
		NewPass: r.PostFormValue("newpass"),
	}

	return req, nil
}

func decodePasswordResetRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := passwordResetRequestReq{
		Email: r.PostFormValue("email"),
	}
	return req, nil
}

func decodePasswordReset(_ context.Context, r *http.Request) (interface{}, error) {
	req := passwordResetReq{
		token:           bone.GetQuery(r, "token")[0],
		Password:        r.PostFormValue("password"),
		ConfirmPassword: r.PostFormValue("confirmPassword"),
	}
	return req, nil
}

func decodeShowPasswordReset(_ context.Context, _ *http.Request) (interface{}, error) {
	return nil, nil
}

func decodeTokenRequest(_ context.Context, r *http.Request) (interface{}, error) {
	identity := r.PostFormValue("email")
	secret := r.PostFormValue("password")

	req := tokenReq{
		Identity: identity,
		Secret:   secret,
	}

	return req, nil
}

func decodeRefreshTokenRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "refresh_token")
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

func decodeUserCreation(_ context.Context, r *http.Request) (interface{}, error) {
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(r.PostFormValue("metadata")), &meta); err != nil {
		return nil, err
	}
	var tags []string
	if err := json.Unmarshal([]byte(r.PostFormValue("tags")), &tags); err != nil {
		return nil, err
	}
	token, err := tokenFromCookie(r, "token")
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
	token, err := tokenFromCookie(r, "token")
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
	token, err := tokenFromCookie(r, "token")
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
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	var data updateUserReq
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return nil, err
	}

	req := updateUserReq{
		token:    token,
		id:       chi.URLParam(r, "id"),
		Name:     data.Name,
		Metadata: data.Metadata,
	}

	return req, nil
}

func decodeUserTagsUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	var data struct {
		Tags []string `json:"tags"`
	}
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return nil, err
	}

	req := updateUserTagsReq{
		token: token,
		id:    chi.URLParam(r, "id"),
		Tags:  data.Tags,
	}

	return req, nil
}

func decodeUserIdentityUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	id := chi.URLParam(r, "id")

	var data updateUserIdentityReq
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return nil, err
	}

	req := updateUserIdentityReq{
		token:    token,
		id:       id,
		Identity: data.Identity,
	}

	return req, nil
}

func decodeUserStatusUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := updateUserStatusReq{
		token:  token,
		UserID: r.PostFormValue("userID"),
	}

	return req, nil
}

func decodeUserRoleUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := updateUserRoleReq{
		token:  token,
		UserID: chi.URLParam(r, "id"),
		Role:   r.PostFormValue("role"),
	}

	return req, nil
}

func decodeAssignGroupRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	return assignReq{
		token:    token,
		GroupID:  chi.URLParam(r, "id"),
		UserID:   r.Form.Get("userID"),
		Relation: r.Form.Get("relation"),
	}, nil
}

func decodeShareThingRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	return shareThingReq{
		token:    token,
		ThingID:  chi.URLParam(r, "id"),
		UserID:   r.Form.Get("userID"),
		Relation: r.Form.Get("relation"),
	}, nil
}

func decodeAddMemberToChannelRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	return addUserToChannelReq{
		token:     token,
		ChannelID: chi.URLParam(r, "id"),
		Relation:  r.Form.Get("relation"),
		UserID:    r.Form.Get("userID"),
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
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}
	credentials := sdk.Credentials{
		Identity: r.PostFormValue("identity"),
		Secret:   r.PostFormValue("secret"),
	}
	thing := sdk.Thing{
		Name:        r.PostFormValue("name"),
		ID:          r.PostFormValue("thingID"),
		Credentials: credentials,
		Tags:        tags,
		Metadata:    meta,
	}
	req := createThingReq{
		token: token,
		Thing: thing,
	}

	return req, nil
}

func decodeThingUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	var data updateThingReq
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return nil, err
	}

	req := updateThingReq{
		token:    token,
		id:       chi.URLParam(r, "id"),
		Name:     data.Name,
		Metadata: data.Metadata,
	}

	return req, nil
}

func decodeThingTagsUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	var data updateThingTagsReq
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return nil, err
	}

	req := updateThingTagsReq{
		token: token,
		id:    chi.URLParam(r, "id"),
		Tags:  data.Tags,
	}

	return req, nil
}

func decodeThingSecretUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	var data updateThingSecretReq
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return nil, err
	}

	req := updateThingSecretReq{
		token:  token,
		id:     chi.URLParam(r, "id"),
		Secret: data.Secret,
	}

	return req, nil
}

func decodeThingStatusUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := updateThingStatusReq{
		token:   token,
		ThingID: r.PostFormValue("thingID"),
	}

	return req, nil
}

func decodeThingsCreation(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
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

	token, err := tokenFromCookie(r, "token")
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
	token, err := tokenFromCookie(r, "token")
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
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	var data updateChannelReq
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return nil, err
	}

	req := updateChannelReq{
		token:       token,
		id:          chi.URLParam(r, "id"),
		Name:        data.Name,
		Metadata:    data.Metadata,
		Description: data.Description,
	}

	return req, nil
}

func decodeConnectChannel(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
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
			token:   token,
			ChanID:  r.Form.Get("channelID"),
			ThingID: chi.URLParam(r, "id"),
			Item:    item,
		}
	case channelsItem:
		req = connectThingReq{
			token:   token,
			ChanID:  chi.URLParam(r, "id"),
			ThingID: r.Form.Get("thingID"),
			Item:    item,
		}
	}

	return req, nil
}

func decodeChannelStatusUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := updateChannelStatusReq{
		token:     token,
		ChannelID: r.PostFormValue("channelID"),
	}

	return req, nil
}

func decodeAddGroupToChannelRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	item, err := readStringQuery(r, itemKey, defKey)
	if err != nil {
		return nil, err
	}

	req := addUserGroupToChannelReq{
		token: token,
		Item:  item,
	}

	switch item {
	case channelsItem:
		req.ChannelID = chi.URLParam(r, "id")
		req.GroupID = r.Form.Get("groupID")
	case groupsItem:
		req.GroupID = chi.URLParam(r, "id")
		req.ChannelID = r.Form.Get("channelID")
	}

	return req, nil
}

func decodeGroupCreation(_ context.Context, r *http.Request) (interface{}, error) {
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(r.PostFormValue("metadata")), &meta); err != nil {
		return nil, err
	}
	token, err := tokenFromCookie(r, "token")
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
	token, err := tokenFromCookie(r, "token")
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
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	var data updateGroupReq
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return nil, err
	}

	req := updateGroupReq{
		token:       token,
		id:          chi.URLParam(r, "id"),
		Name:        data.Name,
		Metadata:    data.Metadata,
		Description: data.Description,
	}
	return req, nil
}

func decodeGroupStatusUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := updateGroupStatusReq{
		token:   token,
		GroupID: r.PostFormValue("groupID"),
	}

	return req, nil
}

func decodePublishRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	msg := messaging.Message{
		Protocol: protocol,
		Channel:  r.Form.Get("channelID"),
		Subtopic: "",
		Payload:  []byte(r.Form.Get("message")),
		Created:  time.Now().UnixNano(),
	}

	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := publishReq{
		Msg:      &msg,
		thingKey: r.Form.Get("thingKey"),
		token:    token,
	}

	return req, nil
}

func decodeReadMessageRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	thKey := r.Form.Get("thingKey")

	if !strings.Contains(thKey, "Thing") {
		thKey = "Thing " + thKey
	}

	page, err := readNumQuery[uint64](r, pageKey, defPage)
	if err != nil {
		return nil, err
	}

	limit, err := readNumQuery[uint64](r, limitKey, defLimit)
	if err != nil {
		return nil, err
	}

	req := readMessageReq{
		token:    token,
		ChanID:   r.Form.Get("chanID"),
		ThingKey: thKey,
		Page:     page,
		Limit:    limit,
	}

	return req, nil
}

func decodeTerminalCommandRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
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
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	var channels []string
	if err := json.Unmarshal([]byte(r.FormValue("channels")), &channels); err != nil {
		return nil, err
	}

	req := createBootstrapReq{
		token:       token,
		ThingID:     r.FormValue("thingID"),
		ExternalID:  r.FormValue("externalID"),
		ExternalKey: r.FormValue("externalKey"),
		Channels:    channels,
		Name:        r.FormValue("name"),
		Content:     r.FormValue("content"),
		ClientCert:  r.FormValue("clientCert"),
		ClientKey:   r.FormValue("clientKey"),
		CACert:      r.FormValue("CACert"),
	}

	return req, nil
}

func decodeUpdateBootstrap(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	var data updateBootstrapReq
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return nil, err
	}
	data.token = token
	data.id = chi.URLParam(r, "id")

	return data, nil
}

func decodeUpdateBootstrapCerts(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	var data updateBootstrapCertReq
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return nil, err
	}
	data.thingID = chi.URLParam(r, "id")
	data.token = token

	return data, nil
}

func decodeUpdateBootstrapConnections(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	var data updateBootstrapConnReq
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return nil, err
	}

	data.id = chi.URLParam(r, "id")
	data.token = token

	return data, nil
}

func decodeListEntityRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
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

	req := listEntityReq{
		token: token,
		page:  page,
		limit: limit,
	}

	return req, nil
}

func decodeListEntityByIDRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
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

	name, err := readStringQuery(r, nameKey, defKey)
	if err != nil {
		return nil, err
	}

	req := listEntityByIDReq{
		token:    token,
		id:       chi.URLParam(r, "id"),
		page:     page,
		limit:    limit,
		relation: relation,
		name:     name,
	}

	return req, nil
}

func decodeGetEntitiesRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
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
		Item:       item,
		Page:       page,
		Name:       name,
		DomainID:   domainID,
		Limit:      limit,
		Permission: permission,
	}

	return req, nil
}

func decodeDomainLoginRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "refresh_token")
	if err != nil {
		return nil, err
	}

	req := domainLoginReq{
		token:    token,
		DomainID: r.FormValue("domainID"),
	}

	return req, nil
}

func decodeCreateDomainRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
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
		token:    token,
		Name:     r.FormValue("name"),
		Alias:    r.FormValue("alias"),
		Tags:     tags,
		Metadata: meta,
	}

	if err != nil {
		return nil, err
	}

	return req, nil
}

func decodeUpdateDomainRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := updateDomainReq{
		token:    token,
		DomainID: chi.URLParam(r, "id"),
	}
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func decodeUpdateDomainTagsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := updateDomainTagsReq{
		token:    token,
		DomainID: chi.URLParam(r, "id"),
	}
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		return nil, err
	}

	return req, nil
}

func decodeDomainStatusUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := updateDomainStatusReq{
		token:    token,
		DomainID: r.PostFormValue("domainID"),
	}

	return req, nil
}

func decodeAssignMemberRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := assignMemberReq{
		token:    token,
		DomainID: chi.URLParam(r, "id"),
		UserID:   r.Form.Get("userID"),
		Relation: r.Form.Get("relation"),
	}

	return req, nil
}

func decodeViewMemberRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	identity, err := readStringQuery(r, identityKey, defKey)
	if err != nil {
		return nil, err
	}

	req := viewMemberReq{
		token:        token,
		UserIdentity: identity,
	}

	return req, nil
}

func decodeSendInvitationRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := sendInvitationReq{
		token:    token,
		DomainID: r.PostFormValue("domainID"),
		UserID:   r.PostFormValue("userID"),
		Relation: r.PostFormValue("relation"),
	}

	return req, nil
}

func decodeListInvitationsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
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
		DomainID: domainID,
		page:     page,
		limit:    limit,
	}

	return req, nil
}

func decodeAcceptInvitationRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	req := acceptInvitationReq{
		token:    token,
		DomainID: r.Form.Get("domainID"),
	}

	return req, nil
}

func decodeDeleteInvitationRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
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
		DomainID: r.Form.Get("domainID"),
		UserID:   r.Form.Get("userID"),
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

func decodePageNotFound(_ context.Context, r *http.Request) (interface{}, error) {
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

func TokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := tokenFromCookie(r, "token")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Parse the token without validation to get the expiration time
		token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
		if err != nil {
			http.Redirect(w, r, "/error?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
			return
		}
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			expirationTime := time.Unix(int64(claims["exp"].(float64)), 0)
			if expirationTime.Before(time.Now()) {
				http.Redirect(w, r, "/token/refresh?referer_url="+url.QueryEscape(r.URL.String()), http.StatusSeeOther)
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
	_, err := w.Write(ar.html)
	if err != nil {
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
	case errors.Contains(err, errConflict):
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
		errors.Contains(err, ui.ErrFailedUnshare):
		w.Header().Set("Location", "/error?error="+url.QueryEscape(displayError.Error()))
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
		errMissingOwner,
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
