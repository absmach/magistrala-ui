// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ultravioletrs/mainflux-ui/ui"

	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/go-zoo/bone"
	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/mainflux/mainflux/pkg/messaging"
	sdk "github.com/mainflux/mainflux/pkg/sdk/go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	contentType = "text/html"
	staticDir   = "ui/web/static"
	protocol    = "http"
)

var (
	errMalformedData     = errors.New("malformed request data")
	errMalformedSubtopic = errors.New("malformed subtopic")
	errNoCookie          = errors.New("failed to read token cookie")
	errUnauthorized      = errors.New("failed to login")
	errAuthentication    = errors.New("failed to perform authentication over the entity")
	errConflict          = errors.New("entity already exists")
	referer              = ""
)

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(svc ui.Service, redirect, instanceID string) http.Handler {
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

	r.Get("/users/policies", kithttp.NewServer(
		listPoliciesEndpoint(svc),
		decodeListPoliciesRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/users/policies", kithttp.NewServer(
		addPolicyEndpoint(svc),
		decodeAddPolicyRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/users/policies/update", kithttp.NewServer(
		updatePolicyEndpoint(svc),
		decodeUpdatePolicyRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/users/policies/delete", kithttp.NewServer(
		deletePolicyEndpoint(svc),
		decodeDeletePolicyRequest,
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

	r.Get("/things/policies", kithttp.NewServer(
		listThingsPoliciesEndpoint(svc),
		decodeListPoliciesRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/things/policies", kithttp.NewServer(
		addThingsPolicyEndpoint(svc),
		decodeAddThingsPolicyRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/things/policies/update", kithttp.NewServer(
		updateThingsPolicyEndpoint(svc),
		decodeUpdatePolicyRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/things/policies/delete", kithttp.NewServer(
		deleteThingsPolicyEndpoint(svc),
		decodeDeleteThingsPolicyRequest,
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
		decodeView,
		encodeResponse,
		opts...,
	))

	r.Post("/things/:id/connect", kithttp.NewServer(
		connectChannelEndpoint(svc),
		decodeConnectChannel,
		encodeResponse,
		opts...,
	))

	r.Post("/disconnectChannel", kithttp.NewServer(
		disconnectChannelEndpoint(svc),
		decodeDisconnectChannel,
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
	r.Post("/channels/:id/connectThing", kithttp.NewServer(
		connectThingEndpoint(svc),
		decodeConnectThing,
		encodeResponse,
		opts...,
	))
	r.Post("/channels/:id/shareThing", kithttp.NewServer(
		shareThingEndpoint(svc),
		decodeShareThingRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/disconnectThing", kithttp.NewServer(
		disconnectThingEndpoint(svc),
		decodeDisconnectThing,
		encodeResponse,
		opts...,
	))

	r.Post("/connect", kithttp.NewServer(
		connectEndpoint(svc),
		decodeConnect,
		encodeResponse,
		opts...,
	))

	r.Post("/disconnect", kithttp.NewServer(
		disconnectEndpoint(svc),
		decodeDisconnect,
		encodeResponse,
		opts...,
	))

	r.Get("/channels/:id/things", kithttp.NewServer(
		listThingsByChannelEndpoint(svc),
		decodeView,
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

	r.Get("/groups/:id/members", kithttp.NewServer(
		listGroupMembersEndpoint(svc),
		decodeView,
		encodeResponse,
		opts...,
	))

	r.Post("/groups/:id", kithttp.NewServer(
		updateGroupEndpoint(svc),
		decodeGroupUpdate,
		encodeResponse,
		opts...,
	))

	r.Post("/groups/:id/members", kithttp.NewServer(
		assignEndpoint(svc),
		decodeAssignRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/groups/:id/unassign", kithttp.NewServer(
		unassignEndpoint(svc),
		decodeUnassignRequest,
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

	r.Post("/readmessages", kithttp.NewServer(
		wsConnectionEndpoint(svc),
		decodeWsConnectionRequest,
		encodeResponse,
		opts...,
	))

	r.Get("/deleted", kithttp.NewServer(
		listDeletedClientsEndpoint(svc),
		decodeListDeletedClientsRequest,
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

	r.GetFunc("/health", mainflux.Health("ui", instanceID))
	r.Handle("/metrics", promhttp.Handler())

	// Static file handler
	fs := http.FileServer(http.Dir(staticDir))
	r.Handle("/*", fs)

	return r
}

func decodeIndexRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	req := indexReq{
		token: token,
	}

	return req, nil
}

func decodeLoginRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	req := loginReq{}

	return req, nil
}

func decodeShowPasswordUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	req := showPasswordUpdateReq{}

	return req, nil
}

func decodePasswordUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
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

func decodeShowPasswordReset(_ context.Context, r *http.Request) (interface{}, error) {
	req := showPasswordResetReq{}

	return req, nil
}

func decodeTokenRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	identity := r.PostFormValue("username")
	secret := r.PostFormValue("password")

	req := tokenReq{
		Identity: identity,
		Secret:   secret,
	}

	return req, nil
}

func decodeRefreshTokenRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	c, err := r.Cookie("refresh_token")
	if err != nil {
		if err == http.ErrNoCookie {
			return nil, errors.Wrap(errNoCookie, err)
		}
		return nil, err
	}
	req := refreshTokenReq{
		refreshToken: c.Value,
		ref:          referer,
	}

	return req, nil
}

func decodeLogoutRequest(_ context.Context, r *http.Request) (interface{}, error) {
	req := sendMessageReq{}

	return req, nil
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
	token, err := getAuthorization(r)
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
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	file, handler, err := r.FormFile("usersFile")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if !strings.HasSuffix(handler.Filename, ".csv") {
		return nil, errors.New("unsupported file type")
	}
	csvr := csv.NewReader(file)

	names := []string{}
	emails := []string{}
	passwords := []string{}
	for {
		row, err := csvr.Read()
		if err != nil {
			if err == io.EOF {
				req := createUsersReq{
					token:     token,
					Names:     names,
					Emails:    emails,
					Passwords: passwords,
				}

				return req, nil
			}

			return nil, err
		}
		names = append(names, string(row[0]))
		emails = append(emails, string(row[1]))
		passwords = append(passwords, string(row[2]))
	}

}

func decodeListUsersRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	req := listUsersReq{
		token: token,
	}

	return req, nil
}

func decodeView(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
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
	token, err := getAuthorization(r)
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
	token, err := getAuthorization(r)
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
	token, err := getAuthorization(r)
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
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}

	req := updateUserStatusReq{
		token:  token,
		UserID: r.PostFormValue("userID"),
	}

	return req, nil
}

func getAuthorization(r *http.Request) (string, error) {
	referer = r.URL.String()
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			return "", errors.Wrap(errNoCookie, err)
		}
		return "", err
	}

	return c.Value, nil
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
	switch {
	case errors.Contains(err, errNoCookie),
		errors.Contains(err, errUnauthorized):
		w.WriteHeader(http.StatusUnauthorized)
	case errors.Contains(err, errMalformedData),
		errors.Contains(err, errMalformedSubtopic):
		w.WriteHeader(http.StatusBadRequest)
	case errors.Contains(err, ui.ErrUnauthorizedAccess):
		w.WriteHeader(http.StatusForbidden)
	case errors.Contains(err, errAuthentication):
		w.Header().Set("Location", "/refresh_token")
		w.WriteHeader(http.StatusSeeOther)
	case errors.Contains(err, errors.ErrLogin):
		w.WriteHeader(http.StatusUnauthorized)
	case errors.Contains(err, errConflict):
		w.WriteHeader(http.StatusConflict)

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

func decodeThingCreation(_ context.Context, r *http.Request) (interface{}, error) {
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(r.PostFormValue("metadata")), &meta); err != nil {
		return nil, err
	}
	var tags []string
	if err := json.Unmarshal([]byte(r.PostFormValue("tags")), &tags); err != nil {
		return nil, err
	}
	token, err := getAuthorization(r)
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

func decodeListThingsRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	req := listThingsReq{
		token: token,
	}

	return req, nil
}

func decodeThingUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
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
	token, err := getAuthorization(r)
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
	token, err := getAuthorization(r)
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
	token, err := getAuthorization(r)
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
	token, err := getAuthorization(r)
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

func decodeThingsCreation(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	file, handler, err := r.FormFile("thingsFile")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if !strings.HasSuffix(handler.Filename, ".csv") {
		return nil, errors.New("unsupported file type")
	}
	csvr := csv.NewReader(file)

	names := []string{}
	for {
		row, err := csvr.Read()
		if err != nil {
			if err == io.EOF {
				req := createThingsReq{
					token: token,
					Names: names,
				}
				return req, nil
			}
			return nil, err
		}
		names = append(names, string(row[0]))
	}
}

func decodeChannelCreation(_ context.Context, r *http.Request) (interface{}, error) {
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(r.PostFormValue("metadata")), &meta); err != nil {
		return nil, err
	}

	token, err := getAuthorization(r)
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
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	file, handler, err := r.FormFile("channelsFile")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if !strings.HasSuffix(handler.Filename, ".csv") {
		return nil, errors.New("unsupported file type")
	}
	csvr := csv.NewReader(file)

	names := []string{}
	for {
		row, err := csvr.Read()
		if err != nil {
			if err == io.EOF {
				req := createChannelsReq{
					token: token,
					Names: names,
				}
				return req, nil
			}
			return nil, err
		}
		names = append(names, string(row[0]))
	}
}

func decodeChannelUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
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

func decodeListChannelsRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	req := listChannelsReq{
		token: token,
	}

	return req, nil
}

func decodeConnectThing(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	chanID := bone.GetValue(r, "id")
	thingID := r.Form.Get("thingID")
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	connIDs := sdk.ConnectionIDs{
		ChannelIDs: []string{chanID},
		ThingIDs:   []string{thingID},
		Actions:    r.PostForm["actions"],
	}
	req := connectThingReq{
		token:   token,
		ConnIDs: connIDs,
	}

	return req, nil
}

func decodeShareThingRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	chanID := bone.GetValue(r, "id")
	userID := r.Form.Get("userID")
	actions := r.PostForm["actions"]
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	req := shareThingReq{
		token:   token,
		ChanID:  chanID,
		UserID:  userID,
		Actions: actions,
	}
	return req, nil

}

func decodeConnectChannel(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	chanID := r.Form.Get("channelID")
	thingID := bone.GetValue(r, "id")
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	connIDs := sdk.ConnectionIDs{
		ChannelIDs: []string{chanID},
		ThingIDs:   []string{thingID},
		Actions:    r.PostForm["actions"],
	}
	req := connectChannelReq{
		token:   token,
		ConnIDs: connIDs,
	}

	return req, nil
}

func decodeConnect(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	file, handler, err := r.FormFile("thingsFile")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if !strings.HasSuffix(handler.Filename, ".csv") {
		return nil, errors.New("unsupported file type")
	}
	csvr := csv.NewReader(file)

	chanID := r.Form.Get("chanID")

	chanIDs := []string{}
	thingIDs := []string{}
	for {
		row, err := csvr.Read()
		if err != nil {
			if err == io.EOF {
				connIDs := sdk.ConnectionIDs{
					ChannelIDs: chanIDs,
					ThingIDs:   thingIDs,
				}
				req := connectReq{
					token:   token,
					ConnIDs: connIDs,
				}

				return req, nil
			}

			return nil, err
		}
		thingIDs = append(thingIDs, string(row[0]))
		chanIDs = append(chanIDs, chanID)
	}
}

func decodeDisconnectThing(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	chanID := r.Form.Get("channelID")
	thingID := r.Form.Get("thingID")
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	req := disconnectThingReq{
		token:   token,
		ChanID:  chanID,
		ThingID: thingID,
	}

	return req, nil
}

func decodeDisconnectChannel(_ context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	chanID := r.Form.Get("channelID")
	thingID := r.Form.Get("thingID")
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	req := disconnectChannelReq{
		token:   token,
		ChanID:  chanID,
		ThingID: thingID,
	}

	return req, nil
}

func decodeDisconnect(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	file, handler, err := r.FormFile("thingsFile")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if !strings.HasSuffix(handler.Filename, ".csv") {
		return nil, errors.New("unsupported file type")
	}
	csvr := csv.NewReader(file)

	chanID := r.Form.Get("chanID")

	chanIDs := []string{}
	thingIDs := []string{}
	for {
		row, err := csvr.Read()
		if err != nil {
			if err == io.EOF {
				connIDs := sdk.ConnectionIDs{
					ChannelIDs: chanIDs,
					ThingIDs:   thingIDs,
				}
				req := disconnectReq{
					token:   token,
					ConnIDs: connIDs,
				}

				return req, nil
			}

			return nil, err
		}
		thingIDs = append(thingIDs, string(row[0]))
		chanIDs = append(chanIDs, chanID)
	}
}

func decodeChannelStatusUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}

	req := updateChannelStatusReq{
		token:     token,
		ChannelID: r.PostFormValue("channelID"),
	}

	return req, nil
}

func decodeAddThingsPolicyRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}

	policy := sdk.Policy{
		Subject: r.PostFormValue("subject"),
		Object:  r.PostFormValue("object"),
		Actions: r.PostForm["actions"],
	}

	req := addThingsPolicyReq{
		token:  token,
		Policy: policy,
	}

	return req, nil
}

func decodeDeleteThingsPolicyRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}

	policy := sdk.Policy{
		Subject: r.PostFormValue("subject"),
		Object:  r.PostFormValue("object"),
		Actions: r.PostForm["actions"],
	}

	req := deleteThingsPolicyReq{
		token:  token,
		Policy: policy,
	}

	return req, nil
}

func decodeGroupCreation(_ context.Context, r *http.Request) (interface{}, error) {
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(r.PostFormValue("metadata")), &meta); err != nil {
		return nil, err
	}
	token, err := getAuthorization(r)
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
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	file, handler, err := r.FormFile("groupsFile")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	if !strings.HasSuffix(handler.Filename, ".csv") {
		return nil, errors.New("unsupported file type")
	}
	csvr := csv.NewReader(file)

	names := []string{}
	for {
		row, err := csvr.Read()
		if err != nil {
			if err == io.EOF {
				req := createGroupsReq{
					token: token,
					Names: names,
				}
				return req, nil
			}
			return nil, err
		}
		names = append(names, string(row[0]))
	}
}

func decodeListGroupsRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	req := listGroupsReq{
		token: token,
	}

	return req, nil
}

func decodeGroupUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
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
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}

	memberid := r.PostFormValue("memberID")
	memberType := r.PostForm["Type"]

	req := assignReq{
		token:    token,
		groupID:  bone.GetValue(r, "id"),
		MemberID: memberid,
		Type:     memberType,
	}

	return req, nil
}

func decodeUnassignRequest(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	MemberId := r.PostFormValue("memberID")

	req := unassignReq{
		token:    token,
		groupID:  bone.GetValue(r, "id"),
		MemberID: MemberId,
	}

	return req, nil
}

func decodeGroupStatusUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}

	req := updateGroupStatusReq{
		token:   token,
		GroupID: r.PostFormValue("groupID"),
	}

	return req, nil
}

func decodeListPoliciesRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	req := listPoliciesReq{
		token: token,
	}

	return req, nil
}

func decodeAddPolicyRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}

	policy := sdk.Policy{
		Subject: r.PostFormValue("subject"),
		Object:  r.PostFormValue("object"),
		Actions: r.PostForm["actions"],
	}

	req := addPolicyReq{
		token:  token,
		Policy: policy,
	}

	return req, nil
}

func decodeUpdatePolicyRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}

	policy := sdk.Policy{
		Subject: r.Form.Get("subject"),
		Object:  r.Form.Get("object"),
		Actions: r.PostForm["actions"],
	}

	req := updatePolicyReq{
		token:  token,
		Policy: policy,
	}

	return req, nil
}

func decodeDeletePolicyRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}

	policy := sdk.Policy{
		Object:  r.Form.Get("object"),
		Subject: r.Form.Get("subject"),
	}

	req := deletePolicyReq{
		token:  token,
		Policy: policy,
	}

	return req, nil
}

func decodePublishRequest(ctx context.Context, r *http.Request) (interface{}, error) {
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

	token, err := getAuthorization(r)
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

func decodeReadMessageRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}

	req := readMessageReq{
		token: token,
	}

	return req, nil
}

func decodeWsConnectionRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}

	chanID := r.Form.Get("chanID")
	thingKey := r.Form.Get("thingKey")

	req := wsConnectionReq{
		token:    token,
		ChanID:   chanID,
		ThingKey: thingKey,
	}

	return req, nil
}

func decodeListDeletedClientsRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	req := listDeletedClientsReq{
		token: token,
	}

	return req, nil
}

func decodeTerminalCommandRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
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

func decodeListBoostrapRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	req := listBootstrapReq{
		token: token,
	}

	return req, nil
}

func decodeCreateBootstrapRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
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

func decodeUpdateBootstrap(ctx context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
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

func decodeUpdateBootstrapCerts(ctx context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
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

func decodeUpdateBootstrapConnections(ctx context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
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
