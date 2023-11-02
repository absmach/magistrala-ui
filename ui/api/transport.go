// Copyright (c) Mainflux
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

	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/go-zoo/bone"
	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/mainflux/mainflux/pkg/messaging"
	sdk "github.com/mainflux/mainflux/pkg/sdk/go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/ultravioletrs/mainflux-ui/ui"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	contentType = "text/html"
	staticDir   = "ui/web/static"
	protocol    = "http"
	pageKey     = "page"
	limitKey    = "limit"
	itemKey     = "item"
	nameKey     = "name"
	defPage     = 1
	defLimit    = 10
	defName     = ""
	defItem     = ""
)

var (
	errAuthorization      = errors.New("missing or invalid credentials provided")
	errAuthentication     = errors.New("failed to perform authentication over the entity")
	errMalformedEntity    = errors.New("malformed entity specification")
	errConflict           = errors.New("entity already exists")
	errInvalidQueryParams = errors.New("invalid query parameters")
	errFileFormat         = errors.New("invalid file format")
	errInvalidFile        = errors.New("unsupported file type")
	referer               = ""

	clientsHeaderLen = 5
	groupsHeaderLen  = 3
	minRows          = 2
)

type number interface {
	int64 | float64 | uint16 | uint64
}

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(svc ui.Service, instanceID string) http.Handler {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(encodeError),
	}

	r := bone.New()
	r.Get("/", kithttp.NewServer(
		indexEndpoint(svc),
		decodeIndexRequest,
		encodeResponse,
		opts...,
	))

	r.Get("/login", kithttp.NewServer(
		loginEndpoint(svc),
		decodeLoginRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/login", kithttp.NewServer(
		tokenEndpoint(svc),
		decodeTokenRequest,
		encodeResponse,
		opts...,
	))

	r.Get("/refresh_token", kithttp.NewServer(
		refreshTokenEndpoint(svc),
		decodeRefreshTokenRequest,
		encodeResponse,
		opts...,
	))

	r.Get("/logout", kithttp.NewServer(
		logoutEndpoint(svc),
		decodeLogoutRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/password", kithttp.NewServer(
		updatePasswordEndpoint(svc),
		decodePasswordUpdate,
		encodeResponse,
		opts...,
	))

	r.Get("/password", kithttp.NewServer(
		showUpdatePasswordEndpoint(svc),
		decodeShowPasswordUpdate,
		encodeResponse,
		opts...,
	))

	r.Post("/password/reset", kithttp.NewServer(
		passwordResetRequestEndpoint(svc),
		decodePasswordResetRequest,
		encodeResponse,
		opts...,
	))
	r.Post("/reset-request", kithttp.NewServer(
		passwordResetEndpoint(svc),
		decodePasswordReset,
		encodeResponse,
		opts...,
	))

	r.Get("/reset-request", kithttp.NewServer(
		showPasswordResetEndpoint(svc),
		decodeShowPasswordReset,
		encodeResponse,
		opts...,
	))

	r.Post("/users", kithttp.NewServer(
		createUserEndpoint(svc),
		decodeUserCreation,
		encodeResponse,
		opts...,
	))

	r.Post("/users/bulk", kithttp.NewServer(
		createUsersEndpoint(svc),
		decodeUsersCreation,
		encodeResponse,
		opts...,
	))

	r.Get("/users", kithttp.NewServer(
		listUsersEndpoint(svc),
		decodeListUsersRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/users/enabled", kithttp.NewServer(
		enableUserEndpoint(svc),
		decodeUserStatusUpdate,
		encodeResponse,
		opts...,
	))

	r.Post("/users/disabled", kithttp.NewServer(
		disableUserEndpoint(svc),
		decodeUserStatusUpdate,
		encodeResponse,
		opts...,
	))

	r.Get("/users/:id", kithttp.NewServer(
		viewUserEndpoint(svc),
		decodeView,
		encodeResponse,
		opts...,
	))

	r.Post("/users/:id", kithttp.NewServer(
		updateUserEndpoint(svc),
		decodeUserUpdate,
		encodeResponse,
		opts...,
	))

	r.Post("/users/:id/tags", kithttp.NewServer(
		updateUserTagsEndpoint(svc),
		decodeUserTagsUpdate,
		encodeResponse,
		opts...,
	))

	r.Post("/users/:id/identity", kithttp.NewServer(
		updateUserIdentityEndpoint(svc),
		decodeUserIdentityUpdate,
		encodeResponse,
		opts...,
	))

	r.Get("/users/:id/groups", kithttp.NewServer(
		listUserGroupsEndpoint(svc),
		decodeListUserGroupsRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/users/:id/groups/assign", kithttp.NewServer(
		assignGroupEndpoint(svc),
		decodeAssignGroupRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/users/:id/groups/unassign", kithttp.NewServer(
		unassignGroupEndpoint(svc),
		decodeUnassignGroupRequest,
		encodeResponse,
		opts...,
	))

	r.Get("/users/:id/channels", kithttp.NewServer(
		listUserChannelsEndpoint(svc),
		decodeListUserChannelsRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/users/:id/channels/assign", kithttp.NewServer(
		AddChannelToUserEndpoint(svc),
		decodeAddChannelToUserRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/users/:id/channels/unassign", kithttp.NewServer(
		RemoveChannelFromUserEndpoint(svc),
		decodeRemoveChannelFromUserRequest,
		encodeResponse,
		opts...,
	))

	r.Get("/users/:id/things", kithttp.NewServer(
		listUserThingsEndpoint(svc),
		decodeListUserThingsRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/things", kithttp.NewServer(
		createThingEndpoint(svc),
		decodeThingCreation,
		encodeResponse,
		opts...,
	))

	r.Post("/things/bulk", kithttp.NewServer(
		createThingsEndpoint(svc),
		decodeThingsCreation,
		encodeResponse,
		opts...,
	))

	r.Get("/things", kithttp.NewServer(
		listThingsEndpoint(svc),
		decodeListThingsRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/things/enabled", kithttp.NewServer(
		enableThingEndpoint(svc),
		decodeThingStatusUpdate,
		encodeResponse,
		opts...,
	))

	r.Post("/things/disabled", kithttp.NewServer(
		disableThingEndpoint(svc),
		decodeThingStatusUpdate,
		encodeResponse,
		opts...,
	))

	r.Get("/things/:id", kithttp.NewServer(
		viewThingEndpoint(svc),
		decodeView,
		encodeResponse,
		opts...,
	))

	r.Post("/things/:id", kithttp.NewServer(
		updateThingEndpoint(svc),
		decodeThingUpdate,
		encodeResponse,
		opts...,
	))

	r.Post("/things/:id/tags", kithttp.NewServer(
		updateThingTagsEndpoint(svc),
		decodeThingTagsUpdate,
		encodeResponse,
		opts...,
	))

	r.Post("/things/:id/secret", kithttp.NewServer(
		updateThingSecretEndpoint(svc),
		decodeThingSecretUpdate,
		encodeResponse,
		opts...,
	))

	r.Post("/things/:id/owner", kithttp.NewServer(
		updateThingOwnerEndpoint(svc),
		decodeThingOwnerUpdate,
		encodeResponse,
		opts...,
	))

	r.Get("/things/:id/channels", kithttp.NewServer(
		listChannelsByThingEndpoint(svc),
		decodeListEntityByIDRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/things/:id/channels/connect", kithttp.NewServer(
		connectChannelEndpoint(svc),
		decodeConnectChannel,
		encodeResponse,
		opts...,
	))

	r.Post("/things/:id/channels/disconnect", kithttp.NewServer(
		disconnectChannelEndpoint(svc),
		decodeDisconnectChannel,
		encodeResponse,
		opts...,
	))

	r.Post("/things/:id/share", kithttp.NewServer(
		shareThingEndpoint(svc),
		decodeShareThingRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/things/:id/unshare", kithttp.NewServer(
		unshareThingEndpoint(svc),
		decodeShareThingRequest,
		encodeResponse,
		opts...,
	))

	r.Get("/things/:id/users", kithttp.NewServer(
		listThingUsersEndpoint(svc),
		decodeListThingUsersRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/channels", kithttp.NewServer(
		createChannelEndpoint(svc),
		decodeChannelCreation,
		encodeResponse,
		opts...,
	))

	r.Post("/channels/bulk", kithttp.NewServer(
		createChannelsEndpoint(svc),
		decodeChannelsCreation,
		encodeResponse,
		opts...,
	))

	r.Post("/channels/enabled", kithttp.NewServer(
		enableChannelEndpoint(svc),
		decodeChannelStatusUpdate,
		encodeResponse,
		opts...,
	))

	r.Post("/channels/disabled", kithttp.NewServer(
		disableChannelEndpoint(svc),
		decodeChannelStatusUpdate,
		encodeResponse,
		opts...,
	))

	r.Get("/channels/:id", kithttp.NewServer(
		viewChannelEndpoint(svc),
		decodeView,
		encodeResponse,
		opts...,
	))

	r.Post("/channels/:id", kithttp.NewServer(
		updateChannelEndpoint(svc),
		decodeChannelUpdate,
		encodeResponse,
		opts...,
	))

	r.Get("/channels", kithttp.NewServer(
		listChannelsEndpoint(svc),
		decodeListChannelsRequest,
		encodeResponse,
		opts...,
	))
	r.Post("/channels/:id/things/connect", kithttp.NewServer(
		connectThingEndpoint(svc),
		decodeConnectThing,
		encodeResponse,
		opts...,
	))

	r.Post("/channels/:id/things/disconnect", kithttp.NewServer(
		disconnectThingEndpoint(svc),
		decodeDisconnectThing,
		encodeResponse,
		opts...,
	))

	r.Get("/channels/:id/things", kithttp.NewServer(
		listThingsByChannelEndpoint(svc),
		decodeListEntityByIDRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/channels/:id/users/assign", kithttp.NewServer(
		AddUserToChannelEndpoint(svc),
		decodeAddUserToChannelRequest,
		encodeResponse,
		opts...,
	))
	r.Post("/channels/:id/users/unassign", kithttp.NewServer(
		RemoveUserFromChannelEndpoint(svc),
		decodeRemoveUserFromChannelRequest,
		encodeResponse,
		opts...,
	))

	r.Get("/channels/:id/users", kithttp.NewServer(
		ListChannelUsersEndpoint(svc),
		decodeListChannelUsersRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/channels/:id/groups/assign", kithttp.NewServer(
		addUserGroupToChannelEndpoint(svc),
		decodeAddUserGroupToChannelRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/channels/:id/groups/unassign", kithttp.NewServer(
		removeUserGroupFromChannelEndpoint(svc),
		decodeRemoveUserGroupFromChannelRequest,
		encodeResponse,
		opts...,
	))

	r.Get("/channels/:id/groups", kithttp.NewServer(
		ListChannelUserGroupsEndpoint(svc),
		decodeListChannelUserGroupsRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/groups", kithttp.NewServer(
		createGroupEndpoint(svc),
		decodeGroupCreation,
		encodeResponse,
		opts...,
	))

	r.Get("/groups", kithttp.NewServer(
		listGroupsEndpoint(svc),
		decodeListGroupsRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/groups/bulk", kithttp.NewServer(
		createGroupsEndpoint(svc),
		decodeGroupsCreation,
		encodeResponse,
		opts...,
	))

	r.Post("/groups/enabled", kithttp.NewServer(
		enableGroupEndpoint(svc),
		decodeGroupStatusUpdate,
		encodeResponse,
		opts...,
	))

	r.Post("/groups/disabled", kithttp.NewServer(
		disableGroupEndpoint(svc),
		decodeGroupStatusUpdate,
		encodeResponse,
		opts...,
	))

	r.Get("/groups/:id", kithttp.NewServer(
		viewGroupEndpoint(svc),
		decodeView,
		encodeResponse,
		opts...,
	))

	r.Get("/groups/:id/users", kithttp.NewServer(
		listGroupUsersEndpoint(svc),
		decodeListEntityByIDRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/groups/:id", kithttp.NewServer(
		updateGroupEndpoint(svc),
		decodeGroupUpdate,
		encodeResponse,
		opts...,
	))

	r.Post("/groups/:id/users/assign", kithttp.NewServer(
		assignEndpoint(svc),
		decodeAssignRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/groups/:id/users/unassign", kithttp.NewServer(
		unassignEndpoint(svc),
		decodeUnassignRequest,
		encodeResponse,
		opts...,
	))

	r.Get("/groups/:id/parents", kithttp.NewServer(
		listParentsEndpoint(svc),
		decodeListParentsRequest,
		encodeResponse,
		opts...,
	))
	r.Get("/groups/:id/children", kithttp.NewServer(
		listChildrenEndpoint(svc),
		decodeListChildrenRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/groups/:id/channels/assign", kithttp.NewServer(
		addChannelToUserGroupEndpoint(svc),
		decodeAddChannelToUserGroupRequest,
		encodeResponse,
		opts...,
	))
	r.Post("/groups/:id/channels/unassign", kithttp.NewServer(
		removeChannelFromUserGroupEndpoint(svc),
		decodeRemoveChannelFromUserGroupRequest,
		encodeResponse,
		opts...,
	))

	r.Get("/groups/:id/channels", kithttp.NewServer(
		listUserGroupChannelsEndpoint(svc),
		decodeListUserGroupChannelsRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/messages", kithttp.NewServer(
		publishMessageEndpoint(svc),
		decodePublishRequest,
		encodeResponse,
		opts...,
	))

	r.Get("/readmessages", kithttp.NewServer(
		readMessageEndpoint(svc),
		decodeReadMessageRequest,
		encodeResponse,
		opts...,
	))

	r.Get("/bootstraps", kithttp.NewServer(
		listBootstrap(svc),
		decodeListBoostrapRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/bootstraps", kithttp.NewServer(
		createBootstrap(svc),
		decodeCreateBootstrapRequest,
		encodeResponse,
		opts...,
	))

	r.Get("/bootstrap/:id", kithttp.NewServer(
		viewBootstrap(svc),
		decodeView,
		encodeResponse,
		opts...,
	))

	r.Post("/bootstrap/:id", kithttp.NewServer(
		updateBootstrap(svc),
		decodeUpdateBootstrap,
		encodeResponse,
		opts...,
	))

	r.Post("/bootstrap/:id/certs", kithttp.NewServer(
		updateBootstrapCerts(svc),
		decodeUpdateBootstrapCerts,
		encodeResponse,
		opts...,
	))

	r.Post("/bootstrap/:id/connections", kithttp.NewServer(
		updateBootstrapConnections(svc),
		decodeUpdateBootstrapConnections,
		encodeResponse,
		opts...,
	))

	r.Get("/bootstrap/:id/terminal", kithttp.NewServer(
		getTerminalEndpoint(svc),
		decodeView,
		encodeResponse,
		opts...,
	))

	r.Post("/bootstrap/:id/terminal/input", kithttp.NewServer(
		handleTerminalInputEndpoint(svc),
		decodeTerminalCommandRequest,
		encodeJSONResponse,
		opts...,
	))

	r.Get("/entities", kithttp.NewServer(
		getEntitiesEndpoint(svc),
		decodeGetEntitiesRequest,
		encodeResponse,
		opts...,
	))

	r.Get("/error", kithttp.NewServer(
		errorPageEndpoint(svc),
		decodeError,
		encodeResponse,
		opts...,
	))

	r.GetFunc("/health", mainflux.Health("ui", instanceID))
	r.Handle("/metrics", promhttp.Handler())

	r.NotFound(kithttp.NewServer(
		errorPageEndpoint(svc),
		decodePageNotFound,
		encodeResponse,
		opts...,
	))

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
	identity := r.PostFormValue("username")
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

func decodeListUsersRequest(_ context.Context, r *http.Request) (interface{}, error) {
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

func decodeView(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}
	req := viewResourceReq{
		token: token,
		id:    bone.GetValue(r, "id"),
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
		id:       bone.GetValue(r, "id"),
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
		id:    bone.GetValue(r, "id"),
		Tags:  data.Tags,
	}

	return req, nil
}

func decodeUserIdentityUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	id := bone.GetValue(r, "id")

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

func decodeListUserGroupsRequest(_ context.Context, r *http.Request) (interface{}, error) {
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
	req := listEntityByIDReq{
		token: token,
		id:    bone.GetValue(r, "id"),
		limit: limit,
		page:  page,
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

	req := assignReq{
		token:    token,
		UserID:   bone.GetValue(r, "id"),
		GroupID:  r.Form.Get("groupID"),
		Relation: r.Form.Get("relation"),
	}

	return req, nil
}

func decodeUnassignGroupRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	req := assignReq{
		token:    token,
		UserID:   bone.GetValue(r, "id"),
		GroupID:  r.Form.Get("groupID"),
		Relation: r.Form.Get("relation"),
	}

	return req, nil
}

func decodeListUserThingsRequest(_ context.Context, r *http.Request) (interface{}, error) {
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
	req := listEntityByIDReq{
		token: token,
		id:    bone.GetValue(r, "id"),
		limit: limit,
		page:  page,
	}
	return req, nil
}

func decodeAddChannelToUserRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := addUserToChannelReq{
		token:     token,
		UserID:    bone.GetValue(r, "id"),
		Relation:  r.Form.Get("relation"),
		ChannelID: r.Form.Get("channelID"),
	}

	return req, nil
}

func decodeRemoveChannelFromUserRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := addUserToChannelReq{
		token:     token,
		UserID:    bone.GetValue(r, "id"),
		Relation:  r.Form.Get("relation"),
		ChannelID: r.Form.Get("channelID"),
	}

	return req, nil

}

func decodeListUserChannelsRequest(_ context.Context, r *http.Request) (interface{}, error) {
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
	req := listEntityByIDReq{
		token: token,
		id:    bone.GetValue(r, "id"),
		limit: limit,
		page:  page,
	}
	return req, nil
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

func decodeListThingsRequest(_ context.Context, r *http.Request) (interface{}, error) {
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
		id:       bone.GetValue(r, "id"),
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
		id:    bone.GetValue(r, "id"),
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
		id:     bone.GetValue(r, "id"),
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

func decodeThingOwnerUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	var data updateThingOwnerReq
	err = json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		return nil, err
	}

	req := updateThingOwnerReq{
		token: token,
		id:    bone.GetValue(r, "id"),
		Owner: data.Owner,
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

	req := listEntityByIDReq{
		token: token,
		id:    bone.GetValue(r, "id"),
		page:  page,
		limit: limit,
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

func decodeShareThingRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := shareThingReq{
		token:    token,
		ThingID:  bone.GetValue(r, "id"),
		UserID:   r.Form.Get("userID"),
		Relation: r.Form.Get("relation"),
	}

	return req, nil
}

func decodeListThingUsersRequest(_ context.Context, r *http.Request) (interface{}, error) {
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
	req := listEntityByIDReq{
		token: token,
		id:    bone.GetValue(r, "id"),
		limit: limit,
		page:  page,
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
		id:          bone.GetValue(r, "id"),
		Name:        data.Name,
		Metadata:    data.Metadata,
		Description: data.Description,
	}

	return req, nil
}

func decodeListChannelsRequest(_ context.Context, r *http.Request) (interface{}, error) {
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

func decodeConnectThing(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	req := connectThingReq{
		token:   token,
		ChanID:  bone.GetValue(r, "id"),
		ThingID: r.Form.Get("thingID"),
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
	req := connectThingReq{
		token:   token,
		ChanID:  r.Form.Get("channelID"),
		ThingID: bone.GetValue(r, "id"),
	}

	return req, nil
}

func decodeDisconnectThing(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}
	req := connectThingReq{
		token:   token,
		ThingID: r.Form.Get("thingID"),
		ChanID:  bone.GetValue(r, "id"),
	}

	return req, nil
}

func decodeDisconnectChannel(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}
	req := connectThingReq{
		token:   token,
		ChanID:  r.Form.Get("channelID"),
		ThingID: bone.GetValue(r, "id"),
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

func decodeAddUserToChannelRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := addUserToChannelReq{
		token:     token,
		ChannelID: bone.GetValue(r, "id"),
		Relation:  r.Form.Get("relation"),
		UserID:    r.Form.Get("userID"),
	}

	return req, nil

}

func decodeRemoveUserFromChannelRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := addUserToChannelReq{
		token:     token,
		ChannelID: bone.GetValue(r, "id"),
		Relation:  r.Form.Get("relation"),
		UserID:    r.Form.Get("userID"),
	}

	return req, nil

}

func decodeListChannelUsersRequest(_ context.Context, r *http.Request) (interface{}, error) {
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
	req := listEntityByIDReq{
		token: token,
		id:    bone.GetValue(r, "id"),
		limit: limit,
		page:  page,
	}
	return req, nil
}

func decodeAddUserGroupToChannelRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := addUserGroupToChannelReq{
		token:     token,
		ChannelID: bone.GetValue(r, "id"),
		GroupID:   r.Form.Get("groupID"),
	}

	return req, nil

}

func decodeRemoveUserGroupFromChannelRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := addUserGroupToChannelReq{
		token:     token,
		ChannelID: bone.GetValue(r, "id"),
		GroupID:   r.Form.Get("groupID"),
	}

	return req, nil
}

func decodeListChannelUserGroupsRequest(_ context.Context, r *http.Request) (interface{}, error) {
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
	req := listEntityByIDReq{
		token: token,
		id:    bone.GetValue(r, "id"),
		limit: limit,
		page:  page,
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
	group := sdk.Group{
		Name:        r.PostFormValue("name"),
		Description: r.PostFormValue("description"),
		Metadata:    meta,
		ParentID:    r.PostFormValue("parentID"),
	}
	req := createGroupReq{
		token: token,
		Group: group,
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

func decodeListGroupsRequest(_ context.Context, r *http.Request) (interface{}, error) {
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
		id:          bone.GetValue(r, "id"),
		Name:        data.Name,
		Metadata:    data.Metadata,
		Description: data.Description,
	}
	return req, nil
}

func decodeAssignRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	req := assignReq{
		token:    token,
		GroupID:  bone.GetValue(r, "id"),
		UserID:   r.Form.Get("userID"),
		Relation: r.Form.Get("relation"),
	}

	return req, nil
}

func decodeUnassignRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	req := assignReq{
		token:    token,
		GroupID:  bone.GetValue(r, "id"),
		UserID:   r.Form.Get("userID"),
		Relation: r.Form.Get("relation"),
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

func decodeListParentsRequest(_ context.Context, r *http.Request) (interface{}, error) {
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
	req := listEntityByIDReq{
		token: token,
		id:    bone.GetValue(r, "id"),
		limit: limit,
		page:  page,
	}
	return req, nil
}

func decodeListChildrenRequest(_ context.Context, r *http.Request) (interface{}, error) {
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
	req := listEntityByIDReq{
		token: token,
		id:    bone.GetValue(r, "id"),
		limit: limit,
		page:  page,
	}
	return req, nil
}

func decodeAddChannelToUserGroupRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := addUserGroupToChannelReq{
		token:     token,
		GroupID:   bone.GetValue(r, "id"),
		ChannelID: r.Form.Get("channelID"),
	}

	return req, nil
}

func decodeRemoveChannelFromUserGroupRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	req := addUserGroupToChannelReq{
		token:     token,
		GroupID:   bone.GetValue(r, "id"),
		ChannelID: r.Form.Get("channelID"),
	}

	return req, nil

}

func decodeListUserGroupChannelsRequest(_ context.Context, r *http.Request) (interface{}, error) {
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
	req := listEntityByIDReq{
		token: token,
		id:    bone.GetValue(r, "id"),
		limit: limit,
		page:  page,
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
		id:      bone.GetValue(r, "id"),
		command: strings.ReplaceAll(strings.Trim(r.PostFormValue("command"), " "), " ", ","),
	}
	return req, nil
}

func decodeListBoostrapRequest(_ context.Context, r *http.Request) (interface{}, error) {
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
	data.id = bone.GetValue(r, "id")

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
	data.thingID = bone.GetValue(r, "id")
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

	data.id = bone.GetValue(r, "id")
	data.token = token

	return data, nil
}

func decodeGetEntitiesRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := tokenFromCookie(r, "token")
	if err != nil {
		return nil, err
	}

	item, err := readStringQuery(r, itemKey, defItem)
	if err != nil {
		return nil, err
	}
	name, err := readStringQuery(r, nameKey, defName)
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
		token: token,
		Item:  item,
		Page:  page,
		Name:  name,
		Limit: limit,
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

func handleStaticFiles(m *bone.Mux) {
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

func encodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	w.Header().Set("Content-Type", contentType)
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
	if ar, ok := response.(mainflux.Response); ok {
		for k, v := range ar.Headers() {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
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
		w.WriteHeader(http.StatusConflict)
	case errors.Contains(err, errMalformedEntity),
		errors.Contains(err, ui.ErrFailedCreate),
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
		errors.Contains(err, ui.ErrFailedDelete),
		errors.Contains(err, ui.ErrExecTemplate),
		errors.Contains(err, ui.ErrFailedDelete),
		errors.Contains(err, ui.ErrFailedShare),
		errors.Contains(err, ui.ErrFailedUnshare):
		w.Header().Set("Location", "/error?error="+url.QueryEscape(displayError.Error()))
		w.WriteHeader(http.StatusSeeOther)
	case errors.Contains(err, errInvalidFile):
		w.WriteHeader(http.StatusUnsupportedMediaType)
	case errors.Contains(err, errFileFormat):
		w.WriteHeader(http.StatusBadRequest)

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
		w.WriteHeader(http.StatusInternalServerError)
	}
}
