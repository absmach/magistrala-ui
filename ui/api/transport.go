// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/ultravioletrs/mainflux-ui/ui"

	kitot "github.com/go-kit/kit/tracing/opentracing"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/go-zoo/bone"
	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/mainflux/mainflux/pkg/messaging"
	"github.com/mainflux/mainflux/things"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	contentType = "text/html"
	staticDir   = "ui/web/static"
	offsetKey   = "offset"
	limitKey    = "limit"
	nameKey     = "name"
	orderKey    = "order"
	dirKey      = "dir"
	metadataKey = "metadata"
	disconnKey  = "disconnected"
	sharedKey   = "shared"
	defOffset   = 0
	defLimit    = 10
	protocol    = "http"
)

var (
	errMalformedData     = errors.New("malformed request data")
	errMalformedSubtopic = errors.New("malformed subtopic")
	errNoCookie          = errors.New("failed to read token cookie")
	errUnauthorized      = errors.New("failed to login")
	redirectURL          = ""
	// channelPartRegExp    = regexp.MustCompile(`^/channels/([\w\-]+)/messages(/[^?]*)?(\?.*)?$`)
)

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(svc ui.Service, redirect string, tracer opentracing.Tracer) http.Handler {
	redirectURL = redirect
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(encodeError),
	}

	r := bone.New()
	r.Get("/", kithttp.NewServer(
		kitot.TraceServer(tracer, "index")(indexEndpoint(svc)),
		decodeIndexRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/things", kithttp.NewServer(
		kitot.TraceServer(tracer, "create_things")(createThingEndpoint(svc)),
		decodeThingCreation,
		encodeResponse,
		opts...,
	))

	r.Get("/things/:id", kithttp.NewServer(
		kitot.TraceServer(tracer, "view_thing")(viewThingEndpoint(svc)),
		decodeView,
		encodeResponse,
		opts...,
	))

	r.Post("/things/:id", kithttp.NewServer(
		kitot.TraceServer(tracer, "update_thing")(updateThingEndpoint(svc)),
		decodeThingUpdate,
		encodeResponse,
		opts...,
	))

	r.Get("/things", kithttp.NewServer(
		kitot.TraceServer(tracer, "list_things")(listThingsEndpoint(svc)),
		decodeListThingsRequest,
		encodeResponse,
		opts...,
	))

	r.Get("/things/:id/delete", kithttp.NewServer(
		kitot.TraceServer(tracer, "remove_thing")(removeThingEndpoint(svc)),
		decodeView,
		encodeResponse,
		opts...,
	))

	r.Post("/channels", kithttp.NewServer(
		kitot.TraceServer(tracer, "create_channels")(createChannelEndpoint(svc)),
		decodeChannelsCreation,
		encodeResponse,
		opts...,
	))

	r.Get("/channels/:id", kithttp.NewServer(
		kitot.TraceServer(tracer, "view_channel")(viewChannelEndpoint(svc)),
		decodeView,
		encodeResponse,
		opts...,
	))

	r.Post("/channels/:id", kithttp.NewServer(
		kitot.TraceServer(tracer, "update_channel")(updateChannelEndpoint(svc)),
		decodeChannelUpdate,
		encodeResponse,
		opts...,
	))

	r.Get("/channels", kithttp.NewServer(
		kitot.TraceServer(tracer, "list_channels")(listChannelsEndpoint(svc)),
		decodeListChannelsRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/connect", kithttp.NewServer(
		kitot.TraceServer(tracer, "connect_thing")(connectThingEndpoint(svc)),
		decodeConnect,
		encodeResponse,
		opts...,
	))

	r.Get("/things/:id/channels", kithttp.NewServer(
		kitot.TraceServer(tracer, "list_things_by_channel")(listThingsByChannelEndpoint(svc)),
		decodeView,
		encodeResponse,
		opts...,
	))

	r.Get("/groups/:id/members", kithttp.NewServer(
		kitot.TraceServer(tracer, "list_group_members")(listGroupMembersEndpoint(svc)),
		decodeView,
		encodeResponse,
		opts...,
	))

	r.Get("/channels/:id/things", kithttp.NewServer(
		kitot.TraceServer(tracer, "list_channels_by_thing")(listChannelsByThingEndpoint(svc)),
		decodeView,
		encodeResponse,
		opts...,
	))

	r.Post("/disconnect", kithttp.NewServer(
		kitot.TraceServer(tracer, "disconnect_thing")(disconnectThingEndpoint(svc)),
		decodeDisconnectThing,
		encodeResponse,
		opts...,
	))

	r.Post("/disconnect", kithttp.NewServer(
		kitot.TraceServer(tracer, "disconnect_channel")(disconnectChannelEndpoint(svc)),
		decodeDisconnectChannel,
		encodeResponse,
		opts...,
	))

	r.Post("/unassign", kithttp.NewServer(
		kitot.TraceServer(tracer, "unassign")(unassignEndpoint(svc)),
		decodeUnassignRequest,
		encodeResponse,
		opts...,
	))

	r.Get("/channels/:id/delete", kithttp.NewServer(
		kitot.TraceServer(tracer, "remove_channel")(removeChannelEndpoint(svc)),
		decodeView,
		encodeResponse,
		opts...,
	))

	r.Post("/groups", kithttp.NewServer(
		kitot.TraceServer(tracer, "create_groups")(createGroupEndpoint(svc)),
		decodeGroupCreation,
		encodeResponse,
		opts...,
	))

	r.Get("/groups", kithttp.NewServer(
		kitot.TraceServer(tracer, "list_groups")(listGroupsEndpoint(svc)),
		decodeListGroupsRequest,
		encodeResponse,
		opts...,
	))

	r.Get("/groups/:id", kithttp.NewServer(
		kitot.TraceServer(tracer, "view_group")(viewGroupEndpoint(svc)),
		decodeView,
		encodeResponse,
		opts...,
	))

	r.Post("/groups/:id", kithttp.NewServer(
		kitot.TraceServer(tracer, "update_group")(updateGroupEndpoint(svc)),
		decodeGroupUpdate,
		encodeResponse,
		opts...,
	))

	r.Post("/groups/:id/members", kithttp.NewServer(
		kitot.TraceServer(tracer, "assign")(assignEndpoint(svc)),
		decodeAssignRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/groups/:id", kithttp.NewServer(
		kitot.TraceServer(tracer, "update_group")(updateGroupEndpoint(svc)),
		decodeGroupUpdate,
		encodeResponse,
		opts...,
	))

	r.Get("/groups/:id/delete", kithttp.NewServer(
		kitot.TraceServer(tracer, "remove_group")(removeGroupEndpoint(svc)),
		decodeView,
		encodeResponse,
		opts...,
	))

	r.Get("/messages", kithttp.NewServer(
		kitot.TraceServer(tracer, "send_messages")(sendMessageEndpoint(svc)),
		decodeSendMessageRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/messages", kithttp.NewServer(
		kitot.TraceServer(tracer, "publish")(publishMessageEndpoint(svc)),
		decodePublishRequest,
		encodeResponse,
		opts...,
	))

	r.Get("/login", kithttp.NewServer(
		kitot.TraceServer(tracer, "login")(loginEndpoint(svc)),
		decodeLoginRequest,
		encodeResponse,
		opts...,
	))

	r.Post("/login", kithttp.NewServer(
		kitot.TraceServer(tracer, "token")(tokenEndpoint(svc)),
		decodeTokenRequest,
		encodeResponse,
		opts...,
	))

	r.Get("/logout", kithttp.NewServer(
		kitot.TraceServer(tracer, "logout")(logoutEndpoint(svc)),
		decodeLogoutRequest,
		encodeResponse,
		opts...,
	))

	r.GetFunc("/version", mainflux.Health("ui"))
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

func decodeThingCreation(_ context.Context, r *http.Request) (interface{}, error) {
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(r.PostFormValue("metadata")), &meta); err != nil {
		return nil, err
	}

	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}

	req := createThingsReq{
		token:    token,
		Name:     r.PostFormValue("name"),
		Metadata: meta,
	}

	return req, nil
}

func getAuthorization(r *http.Request) (string, error) {
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			return "", errors.Wrap(errNoCookie, err)
		}
		return "", err
	}

	return c.Value, nil
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

func decodeThingUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(r.PostFormValue("metadata")), &meta); err != nil {
		return nil, err
	}

	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	req := updateThingReq{
		token:    token,
		id:       bone.GetValue(r, "id"),
		Name:     r.PostFormValue("name"),
		Metadata: meta,
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

func decodeChannelsCreation(_ context.Context, r *http.Request) (interface{}, error) {
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(r.PostFormValue("metadata")), &meta); err != nil {
		return nil, err
	}
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}

	req := createChannelsReq{
		token:    token,
		Name:     r.PostFormValue("name"),
		Metadata: meta,
	}

	return req, nil
}

func decodeChannelUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(r.PostFormValue("metadata")), &meta); err != nil {
		return nil, err
	}
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	req := updateChannelReq{
		token:    token,
		id:       bone.GetValue(r, "id"),
		Name:     r.PostFormValue("name"),
		Metadata: meta,
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

func decodeConnect(_ context.Context, r *http.Request) (interface{}, error) {
	r.ParseForm()
	chanID := r.Form.Get("chanID")
	thingID := r.Form.Get("thingID")
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	req := connectThingReq{
		token:   token,
		ChanID:  chanID,
		ThingID: thingID,
	}
	return req, nil
}

func decodeDisconnectThing(_ context.Context, r *http.Request) (interface{}, error) {
	r.ParseForm()
	chanID := r.Form.Get("chanID")
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
	r.ParseForm()
	chanID := r.Form.Get("chanID")
	thingID := r.Form.Get("thingID")
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	req := disconnectChannelReq{
		token:   token,
		ThingID: thingID,
		ChanID:  chanID,
	}
	return req, nil
}

func decodeUnassignRequest(_ context.Context, r *http.Request) (interface{}, error) {
	r.ParseForm()
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	req := unassignReq{
		assignReq{
			token:   token,
			groupID: r.PostFormValue("groupId"),
			Type:    r.PostFormValue("Type"),
			Member:  r.PostFormValue("memberId"),
		},
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
	req := createGroupsReq{
		token:       token,
		Name:        r.PostFormValue("name"),
		Description: r.PostFormValue("description"),
		ParentID:    r.PostFormValue("parentid"),
		Metadata:    meta,
	}

	return req, nil
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

func decodeAssignRequest(_ context.Context, r *http.Request) (interface{}, error) {
	memberid := r.PostFormValue("memberId")
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	req := assignReq{
		token:   token,
		groupID: bone.GetValue(r, "id"),
		Type:    r.PostFormValue("Type"),
		Member:  memberid,
	}
	println(req.Type)
	return req, nil
}

func decodeGroupUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(r.PostFormValue("metadata")), &meta); err != nil {
		return nil, err
	}
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	req := updateGroupReq{
		token:    token,
		id:       bone.GetValue(r, "id"),
		Name:     r.PostFormValue("name"),
		Metadata: meta,
	}
	return req, nil
}

func decodePublishRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	chanID := r.PostFormValue("chanID")
	payload := r.PostFormValue("message")
	thingKey := r.PostFormValue("thingKey")

	msg := messaging.Message{
		Protocol: protocol,
		Channel:  chanID,
		Subtopic: "",
		Payload:  []byte(payload),
		Created:  time.Now().UnixNano(),
	}

	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}

	req := publishReq{
		msg:      msg,
		thingKey: thingKey,
		token:    token,
	}

	return req, nil
}

func decodeTokenRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	username := r.PostFormValue("username")
	password := r.PostFormValue("password")

	req := tokenReq{
		username: username,
		password: password,
	}

	return req, nil
}

func decodeLogoutRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	req := sendMessageReq{}
	return req, nil
}

func decodeSendMessageRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	token, err := getAuthorization(r)
	if err != nil {
		return nil, err
	}
	req := sendMessageReq{
		token: token,
	}

	return req, nil
}

func decodePayload(body io.ReadCloser) ([]byte, error) {
	payload, err := ioutil.ReadAll(body)
	if err != nil {
		return nil, errMalformedData
	}
	defer body.Close()

	return payload, nil
}

func encodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	w.Header().Set("Content-Type", contentType)
	ar, ok := response.(uiRes)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return nil
	}

	for k, v := range ar.Headers() {
		w.Header().Set(k, v)
	}
	w.WriteHeader(ar.Code())

	if ar.Empty() {
		return nil
	}
	w.Write(ar.html)
	return nil
}

func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	switch true {
	case errors.Contains(err, errNoCookie),
		errors.Contains(err, errUnauthorized):
		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
	case errors.Contains(err, errMalformedData),
		errors.Contains(err, errMalformedSubtopic):
		w.WriteHeader(http.StatusBadRequest)
	case errors.Contains(err, things.ErrUnauthorizedAccess):
		w.WriteHeader(http.StatusForbidden)
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
