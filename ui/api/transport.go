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
	"strconv"
	"strings"
	"time"

	"github.com/absmach/magistrala"
	"github.com/absmach/magistrala-ui/ui"
	"github.com/absmach/magistrala-ui/ui/oauth2"
	"github.com/absmach/magistrala/pkg/errors"
	sdk "github.com/absmach/magistrala/pkg/sdk/go"
	"github.com/go-chi/chi/v5"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/go-zoo/bone"
	"github.com/golang-jwt/jwt"
	"github.com/gorilla/securecookie"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	htmContentType          = "text/html"
	jsonContentType         = "application/json"
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
	formatKey               = "format"
	subtopicKey             = "subtopic"
	publisherKey            = "publisher"
	protocolKey             = "protocol"
	valueKey                = "v"
	stringValueKey          = "vs"
	dataValueKey            = "vd"
	boolValueKey            = "vb"
	comparatorKey           = "comparator"
	fromKey                 = "from"
	toKey                   = "to"
	aggregationKey          = "aggregation"
	intervalKey             = "interval"
	defInterval             = "1s"
	defPage                 = 1
	defLimit                = 10
	defKey                  = ""
	usersAPIEndpoint        = "users"
	thingsAPIEndpoint       = "things"
	channelsAPIEndpoint     = "channels"
	groupsAPIEndpoint       = "groups"
	bootstrapAPIEndpoint    = "bootstraps"
	membersAPIEndpoint      = "domains/members"
	loginAPIEndpoint        = "login"
	tokenRefreshAPIEndpoint = "token/refresh"
	domainsAPIEndpoint      = "domains"
	errorAPIEndpoint        = "error"
	thingsItem              = "things"
	channelsItem            = "channels"
	groupsItem              = "groups"
	accessTokenKey          = "access_token"
	refreshTokenKey         = "refresh_token"
	sessionDetailsKey       = "session"
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
func MakeHandler(svc ui.Service, r *chi.Mux, instanceID, prefix string, secureCookie *securecookie.SecureCookie, providers ...oauth2.Provider) (http.Handler, error) {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(encodeError(prefix)),
	}

	var pathPrefix string
	if prefix != "" {
		pathPrefix = prefix
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, fmt.Sprintf("%s/", prefix), http.StatusSeeOther)
		})
	} else {
		pathPrefix = "/"
	}

	r.Route(pathPrefix, func(r chi.Router) {
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
			refreshTokenEndpoint(svc, secureCookie, prefix),
			decodeRefreshTokenRequest(secureCookie),
			encodeResponse,
			opts...,
		).ServeHTTP)

		r.Get("/tokens/secure", kithttp.NewServer(
			secureTokenEndpoint(svc, secureCookie, prefix),
			decodeSecureTokenRequest,
			encodeResponse,
			opts...,
		).ServeHTTP)

		r.Get("/logout", kithttp.NewServer(
			logoutEndpoint(svc, prefix),
			decodeLogoutRequest,
			encodeResponse,
			opts...,
		).ServeHTTP)

		for _, provider := range providers {
			if provider.IsEnabled() {
				r.HandleFunc("/signup/"+provider.Name(), oauth2Handler(oauth2.SignUp, provider))
				r.HandleFunc("/signin/"+provider.Name(), oauth2Handler(oauth2.SignIn, provider))
			}
		}

		r.Post("/reset-request", kithttp.NewServer(
			passwordResetRequestEndpoint(svc, prefix),
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
			passwordResetEndpoint(svc, prefix),
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

		r.Route("/", func(r chi.Router) {
			r.Use(DecryptCookieMiddleware(secureCookie, prefix))
			r.Use(TokenMiddleware(prefix))
			r.Route("/", func(r chi.Router) {
				r.Use(AuthnMiddleware(prefix))
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
					updatePasswordEndpoint(svc, prefix),
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
					r.Use(AdminAuthMiddleware(prefix))
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
						enableUserEndpoint(svc, prefix),
						decodeUserStatusUpdate,
						encodeResponse,
						opts...,
					).ServeHTTP)

					r.Post("/disable", kithttp.NewServer(
						disableUserEndpoint(svc, prefix),
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
						updateUserRoleEndpoint(svc, prefix),
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
						enableThingEndpoint(svc, prefix),
						decodeThingStatusUpdate,
						encodeResponse,
						opts...,
					).ServeHTTP)

					r.Post("/disable", kithttp.NewServer(
						disableThingEndpoint(svc, prefix),
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
						connectChannelEndpoint(svc, prefix),
						decodeConnectChannel,
						encodeResponse,
						opts...,
					).ServeHTTP)

					r.Post("/{id}/channels/disconnect", kithttp.NewServer(
						disconnectChannelEndpoint(svc, prefix),
						decodeConnectChannel,
						encodeResponse,
						opts...,
					).ServeHTTP)

					r.Post("/{id}/share", kithttp.NewServer(
						shareThingEndpoint(svc, prefix),
						decodeShareThingRequest,
						encodeResponse,
						opts...,
					).ServeHTTP)

					r.Post("/{id}/unshare", kithttp.NewServer(
						unshareThingEndpoint(svc, prefix),
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
						enableChannelEndpoint(svc, prefix),
						decodeChannelStatusUpdate,
						encodeResponse,
						opts...,
					).ServeHTTP)

					r.Post("/disable", kithttp.NewServer(
						disableChannelEndpoint(svc, prefix),
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
						connectChannelEndpoint(svc, prefix),
						decodeConnectChannel,
						encodeResponse,
						opts...,
					).ServeHTTP)

					r.Post("/{id}/things/disconnect", kithttp.NewServer(
						disconnectChannelEndpoint(svc, prefix),
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
						AddMemberToChannelEndpoint(svc, prefix),
						decodeAddMemberToChannelRequest,
						encodeResponse,
						opts...,
					).ServeHTTP)

					r.Post("/{id}/users/unassign", kithttp.NewServer(
						RemoveMemberFromChannelEndpoint(svc, prefix),
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
						addGroupToChannelEndpoint(svc, prefix),
						decodeAddGroupToChannelRequest,
						encodeResponse,
						opts...,
					).ServeHTTP)

					r.Post("/{id}/groups/unassign", kithttp.NewServer(
						removeGroupFromChannelEndpoint(svc, prefix),
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
						enableGroupEndpoint(svc, prefix),
						decodeGroupStatusUpdate,
						encodeResponse,
						opts...,
					).ServeHTTP)

					r.Post("/disable", kithttp.NewServer(
						disableGroupEndpoint(svc, prefix),
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
						assignGroupEndpoint(svc, prefix),
						decodeAssignGroupRequest,
						encodeResponse,
						opts...,
					).ServeHTTP)

					r.Post("/{id}/users/unassign", kithttp.NewServer(
						unassignGroupEndpoint(svc, prefix),
						decodeAssignGroupRequest,
						encodeResponse,
						opts...,
					).ServeHTTP)

					r.Post("/{id}/channels/assign", kithttp.NewServer(
						addGroupToChannelEndpoint(svc, prefix),
						decodeAddGroupToChannelRequest,
						encodeResponse,
						opts...,
					).ServeHTTP)
					r.Post("/{id}/channels/unassign", kithttp.NewServer(
						removeGroupFromChannelEndpoint(svc, prefix),
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
						publishMessageEndpoint(svc, prefix),
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

				r.Get("/data", kithttp.NewServer(
					FetchChartDataEndpoint(svc),
					decodeReadMessagesRequest,
					encodeResponse,
					opts...,
				).ServeHTTP)

				r.Route("/bootstraps", func(r chi.Router) {
					r.Get("/", kithttp.NewServer(
						listBootstrap(svc),
						decodeListEntityRequest,
						encodeResponse,
						opts...,
					).ServeHTTP)

					r.Post("/", kithttp.NewServer(
						createBootstrap(svc, prefix),
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
						deleteBootstrapEndpoint(svc, prefix),
						decodeDeleteBootstrap,
						encodeResponse,
						opts...,
					).ServeHTTP)

					r.Post("/{id}/state", kithttp.NewServer(
						updateBootstrapStateEndpoint(svc, prefix),
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
						updateBootstrapConnections(svc, prefix),
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
						acceptInvitationEndpoint(svc, prefix),
						decodeAcceptInvitationRequest,
						encodeResponse,
						opts...,
					).ServeHTTP)

					r.Post("/delete", kithttp.NewServer(
						deleteInvitationEndpoint(svc, prefix),
						decodeDeleteInvitationRequest,
						encodeResponse,
						opts...,
					).ServeHTTP)
				})
			})
			r.Route("/domains", func(r chi.Router) {
				r.Post("/login", kithttp.NewServer(
					domainLoginEndpoint(svc, secureCookie, prefix),
					decodeDomainLoginRequest(secureCookie),
					encodeResponse,
					opts...,
				).ServeHTTP)

				r.Post("/", kithttp.NewServer(
					createDomainEndpoint(svc, prefix),
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
					enableDomainEndpoint(svc, prefix),
					decodeDomainStatusUpdate,
					encodeResponse,
					opts...,
				).ServeHTTP)

				r.Post("/disable", kithttp.NewServer(
					disableDomainEndpoint(svc, prefix),
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
					assignMemberEndpoint(svc, prefix),
					decodeAssignMemberRequest,
					encodeResponse,
					opts...,
				).ServeHTTP)

				r.Post("/{id}/unassign", kithttp.NewServer(
					unassignMemberEndpoint(svc, prefix),
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

	if err := handleStaticFiles(r); err != nil {
		return nil, err
	}

	return r, nil
}

func decodeIndexRequest(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}

	return indexReq{
		Session: session,
	}, nil
}

func decodeViewRegistrationRequest(_ context.Context, _ *http.Request) (interface{}, error) {
	return nil, nil
}

func decodeCreateDashboardRequest(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	var data createDashboardReq
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		return nil, err
	}

	return createDashboardReq{
		token:       session.Token,
		Name:        data.Name,
		Description: data.Description,
	}, nil
}

func decodeListDashboardsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
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

	return listDashboardsReq{
		token: session.Token,
		page:  page,
		limit: limit,
	}, nil
}

func decodeDashboardRequest(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	return dashboardsReq{
		Session: session,
	}, nil
}

func decodeUpdateDashboardRequest(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	var data updateDashboardReq
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		return nil, err
	}

	return updateDashboardReq{
		token:       session.Token,
		ID:          data.ID,
		Name:        data.Name,
		Description: data.Description,
		Metadata:    data.Metadata,
		Layout:      data.Layout,
	}, nil
}

func decodeDeleteDashboardRequest(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	var data deleteDashboardReq
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		return nil, err
	}

	return deleteDashboardReq{
		token: session.Token,
		ID:    data.ID,
	}, nil
}

func decodeViewDashboardRequest(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}

	return viewDashboardReq{
		DashboardID: chi.URLParam(r, "id"),
		Session:     session,
	}, nil
}

func decodeLoginRequest(_ context.Context, _ *http.Request) (interface{}, error) {
	return nil, nil
}

func decodeShowPasswordUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	return showUpdatePasswordReq{
		Session: session,
	}, nil
}

func decodePasswordUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	return updateUserPasswordReq{
		token:   session.Token,
		oldPass: r.PostFormValue("oldpass"),
		newPass: r.PostFormValue("newpass"),
	}, nil
}

func decodePasswordResetRequest(_ context.Context, r *http.Request) (interface{}, error) {
	return passwordResetRequestReq{
		email: r.PostFormValue("email"),
	}, nil
}

func decodePasswordReset(_ context.Context, r *http.Request) (interface{}, error) {
	accessToken, err := readStringQuery(r, accessTokenKey, defKey)
	if err != nil {
		return nil, err
	}

	return passwordResetReq{
		token:           accessToken,
		password:        r.PostFormValue("password"),
		confirmPassword: r.PostFormValue("confirmPassword"),
	}, nil
}

func decodeShowPasswordReset(_ context.Context, _ *http.Request) (interface{}, error) {
	return nil, nil
}

func decodeRegisterUserRequest(_ context.Context, r *http.Request) (interface{}, error) {
	return registerUserReq{
		User: sdk.User{
			Name: r.PostFormValue("name"),
			Credentials: sdk.Credentials{
				Identity: r.PostFormValue("email"),
				Secret:   r.PostFormValue("password"),
			},
		},
	}, nil
}

func decodeTokenRequest(_ context.Context, r *http.Request) (interface{}, error) {
	return tokenReq{
		sdk.Login{
			Identity: r.PostFormValue("email"),
			Secret:   r.PostFormValue("password"),
		},
	}, nil
}

func decodeSecureTokenRequest(_ context.Context, r *http.Request) (interface{}, error) {
	accessToken, err := tokenFromCookie(r, accessTokenKey)
	if err != nil {
		return nil, err
	}
	refreshToken, err := tokenFromCookie(r, refreshTokenKey)
	if err != nil {
		return nil, err
	}

	return secureTokenReq{
		Token: sdk.Token{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	}, nil
}

func decodeRefreshTokenRequest(s *securecookie.SecureCookie) kithttp.DecodeRequestFunc {
	return func(_ context.Context, r *http.Request) (interface{}, error) {
		sessionCookie, err := tokenFromCookie(r, sessionDetailsKey)
		if err != nil {
			return nil, err
		}
		refreshTokenCookie, err := tokenFromCookie(r, refreshTokenKey)
		if err != nil {
			return nil, err
		}

		var session string
		if err := s.Decode(sessionDetailsKey, sessionCookie, &session); err != nil {
			return nil, err
		}
		var sessionDetails ui.Session
		if err := json.Unmarshal([]byte(session), &sessionDetails); err != nil {
			return ui.Session{}, err
		}

		var refreshToken string
		if err := s.Decode(refreshTokenKey, refreshTokenCookie, &refreshToken); err != nil {
			return ui.Session{}, err
		}
		sessionDetails.Token = refreshToken

		referer, err := readStringQuery(r, refererKey, defKey)
		if err != nil {
			return nil, err
		}

		return refreshTokenReq{
			Session: sessionDetails,
			ref:     referer,
		}, nil
	}
}

func decodeLogoutRequest(_ context.Context, _ *http.Request) (interface{}, error) {
	return nil, nil
}

func oauth2Handler(state oauth2.State, provider oauth2.Provider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var url string
		var err error
		switch state {
		case oauth2.SignIn:
			url, err = provider.GenerateSignInURL()
		case oauth2.SignUp:
			url, err = provider.GenerateSignUpURL()
		default:
			err = fmt.Errorf("invalid state")
		}

		if err != nil {
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return
		}

		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

func decodeUserCreation(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(r.PostFormValue("metadata")), &meta); err != nil {
		return nil, err
	}
	var tags []string
	if err := json.Unmarshal([]byte(r.PostFormValue("tags")), &tags); err != nil {
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

	return createUserReq{
		token: session.Token,
		User:  user,
	}, nil
}

func decodeUsersCreation(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
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

	return createUsersReq{
		token: session.Token,
		users: users,
	}, nil
}

func decodeView(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}

	return viewResourceReq{
		id:      chi.URLParam(r, "id"),
		Session: session,
	}, nil
}

func decodeUserUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	var user sdk.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		return nil, err
	}
	user.ID = chi.URLParam(r, "id")

	return updateUserReq{
		token: session.Token,
		User:  user,
	}, nil
}

func decodeUserTagsUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	var user sdk.User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		return nil, err
	}
	user.ID = chi.URLParam(r, "id")

	return updateUserTagsReq{
		token: session.Token,
		User:  user,
	}, nil
}

func decodeUserIdentityUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	var credentials sdk.Credentials
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		return nil, err
	}

	return updateUserIdentityReq{
		token: session.Token,
		User: sdk.User{
			ID:          chi.URLParam(r, "id"),
			Credentials: credentials,
		},
	}, nil
}

func decodeUserStatusUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	return updateUserStatusReq{
		token: session.Token,
		id:    r.PostFormValue("entityID"),
	}, nil
}

func decodeUserRoleUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	return updateUserRoleReq{
		token: session.Token,
		User: sdk.User{
			ID:   chi.URLParam(r, "id"),
			Role: r.PostFormValue("role"),
		},
	}, nil
}

func decodeAssignGroupRequest(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	return assignReq{
		token:   session.Token,
		groupID: chi.URLParam(r, "id"),
		UsersRelationRequest: sdk.UsersRelationRequest{
			UserIDs:  r.Form["userID"],
			Relation: r.Form.Get("relation"),
		},
	}, nil
}

func decodeShareThingRequest(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	return shareThingReq{
		token: session.Token,
		id:    chi.URLParam(r, "id"),
		UsersRelationRequest: sdk.UsersRelationRequest{
			UserIDs:  r.Form["userID"],
			Relation: r.Form.Get("relation"),
		},
	}, nil
}

func decodeAddMemberToChannelRequest(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	return addUserToChannelReq{
		token:     session.Token,
		ChannelID: chi.URLParam(r, "id"),
		UsersRelationRequest: sdk.UsersRelationRequest{
			Relation: r.Form.Get("relation"),
			UserIDs:  r.Form["userID"],
		},
	}, nil
}

func decodeThingCreation(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(r.PostFormValue("metadata")), &meta); err != nil {
		return nil, err
	}
	var tags []string
	if err := json.Unmarshal([]byte(r.PostFormValue("tags")), &tags); err != nil {
		return nil, err
	}

	return createThingReq{
		token: session.Token,
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
	}, nil
}

func decodeThingUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	var thing sdk.Thing
	if err := json.NewDecoder(r.Body).Decode(&thing); err != nil {
		return nil, err
	}
	thing.ID = chi.URLParam(r, "id")

	return updateThingReq{
		token: session.Token,
		Thing: thing,
	}, nil
}

func decodeThingTagsUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	var thing sdk.Thing
	if err := json.NewDecoder(r.Body).Decode(&thing); err != nil {
		return nil, err
	}
	thing.ID = chi.URLParam(r, "id")

	return updateThingTagsReq{
		token: session.Token,
		Thing: thing,
	}, nil
}

func decodeThingSecretUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	var credentials sdk.Credentials
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		return nil, err
	}

	return updateThingSecretReq{
		token: session.Token,
		Thing: sdk.Thing{
			ID:          chi.URLParam(r, "id"),
			Credentials: credentials,
		},
	}, nil
}

func decodeThingStatusUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	return updateThingStatusReq{
		token: session.Token,
		id:    r.PostFormValue("entityID"),
	}, nil
}

func decodeThingsCreation(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
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

	return createThingsReq{
		token:  session.Token,
		things: things,
	}, nil
}

func decodeChannelCreation(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(r.PostFormValue("metadata")), &meta); err != nil {
		return nil, err
	}

	ch := sdk.Channel{
		Name:        r.PostFormValue("name"),
		Description: r.PostFormValue("description"),
		Metadata:    meta,
		ParentID:    r.PostFormValue("parentID"),
	}

	return createChannelReq{
		token:   session.Token,
		Channel: ch,
	}, nil
}

func decodeChannelsCreation(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
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

	return createChannelsReq{
		token:    session.Token,
		Channels: channels,
	}, nil
}

func decodeChannelUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	var channel sdk.Channel
	if err := json.NewDecoder(r.Body).Decode(&channel); err != nil {
		return nil, err
	}
	channel.ID = chi.URLParam(r, "id")

	return updateChannelReq{
		token:   session.Token,
		Channel: channel,
	}, nil
}

func decodeConnectChannel(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
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
			token:     session.Token,
			channelID: r.Form.Get("channelID"),
			thingID:   chi.URLParam(r, "id"),
			item:      item,
		}
	case channelsItem:
		req = connectThingReq{
			token:     session.Token,
			channelID: chi.URLParam(r, "id"),
			thingID:   r.Form.Get("thingID"),
			item:      item,
		}
	}

	return req, nil
}

func decodeChannelStatusUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	return updateChannelStatusReq{
		token: session.Token,
		id:    r.PostFormValue("entityID"),
	}, nil
}

func decodeAddGroupToChannelRequest(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
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

	req := addUserGroupToChannelReq{
		token: session.Token,
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
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(r.PostFormValue("metadata")), &meta); err != nil {
		return nil, err
	}

	return createGroupReq{
		token: session.Token,
		Group: sdk.Group{
			Name:        r.PostFormValue("name"),
			Description: r.PostFormValue("description"),
			Metadata:    meta,
			ParentID:    r.PostFormValue("parentID"),
		},
	}, nil
}

func decodeGroupsCreation(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
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

	return createGroupsReq{
		token:  session.Token,
		Groups: groups,
	}, nil
}

func decodeGroupUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}

	var group sdk.Group
	if err := json.NewDecoder(r.Body).Decode(&group); err != nil {
		return nil, err
	}
	group.ID = chi.URLParam(r, "id")

	return updateGroupReq{
		token: session.Token,
		Group: group,
	}, nil
}

func decodeGroupStatusUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	return updateGroupStatusReq{
		token: session.Token,
		id:    r.PostFormValue("entityID"),
	}, nil
}

func decodePublishRequest(_ context.Context, r *http.Request) (interface{}, error) {
	floatValue, err := strconv.ParseFloat(r.PostFormValue("value"), 64)
	if err != nil {
		return nil, err
	}

	return publishReq{
		thingKey:  r.PostFormValue("thingKey"),
		channelID: r.PostFormValue("channelID"),
		Message: ui.Message{
			BaseTime: float64(time.Now().UnixNano()),
			BaseUnit: r.PostFormValue("unit"),
			Name:     r.PostFormValue("name"),
			Unit:     r.PostFormValue("unit"),
			Value:    floatValue,
		},
	}, nil
}

func decodeReadMessagesRequest(_ context.Context, r *http.Request) (interface{}, error) {
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

	subtopic, err := readStringQuery(r, subtopicKey, "")
	if err != nil {
		return nil, err
	}

	publisher, err := readStringQuery(r, publisherKey, "")
	if err != nil {
		return nil, err
	}

	protocol, err := readStringQuery(r, protocolKey, "")
	if err != nil {
		return nil, err
	}

	name, err := readStringQuery(r, nameKey, "")
	if err != nil {
		return nil, err
	}

	v, err := readNumQuery[float64](r, valueKey, 0)
	if err != nil {
		return nil, err
	}

	vs, err := readStringQuery(r, stringValueKey, "")
	if err != nil {
		return nil, err
	}

	vd, err := readStringQuery(r, dataValueKey, "")
	if err != nil {
		return nil, err
	}

	vb, err := readBoolQuery(r, boolValueKey, false)
	if err != nil {
		return nil, err
	}

	from, err := readNumQuery[float64](r, fromKey, 0)
	if err != nil {
		return nil, err
	}

	to, err := readNumQuery[float64](r, toKey, 0)
	if err != nil {
		return nil, err
	}

	aggregation, err := readStringQuery(r, aggregationKey, "")
	if err != nil {
		return nil, err
	}

	var interval string
	if aggregation != "" {
		interval, err = readStringQuery(r, intervalKey, defInterval)
		if err != nil {
			return nil, err
		}
	}

	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}

	offset := (page - 1) * limit

	return readMessagesReq{
		channelID: r.Form.Get("channel"),
		thingKey:  r.Form.Get("thing"),
		Session:   session,
		mpgm: sdk.MessagePageMetadata{
			PageMetadata: sdk.PageMetadata{
				Limit:  limit,
				Offset: offset,
				Name:   name,
			},
			Subtopic:    subtopic,
			Publisher:   publisher,
			Protocol:    protocol,
			Value:       v,
			StringValue: vs,
			DataValue:   vd,
			BoolValue:   &vb,
			From:        from * ui.MilliToNanoConverter,
			To:          to * ui.MilliToNanoConverter,
			Aggregation: aggregation,
			Interval:    interval,
		},
	}, nil
}

func decodeTerminalCommandRequest(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	return bootstrapCommandReq{
		token:   session.Token,
		id:      chi.URLParam(r, "id"),
		command: strings.ReplaceAll(strings.Trim(r.PostFormValue("command"), " "), " ", ","),
	}, nil
}

func decodeCreateBootstrapRequest(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	return createBootstrapReq{
		token: session.Token,
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
	}, nil
}

func decodeUpdateBootstrap(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	var config sdk.BootstrapConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		return nil, err
	}
	config.ThingID = chi.URLParam(r, "id")

	return updateBootstrapReq{
		token:           session.Token,
		BootstrapConfig: config,
	}, nil
}

func decodeDeleteBootstrap(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	return deleteBootstrapReq{
		token: session.Token,
		id:    chi.URLParam(r, "id"),
	}, nil
}

func decodeUpdateBootstrapState(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	state, err := strconv.Atoi(r.FormValue("state"))
	if err != nil {
		return nil, err
	}

	return updateBootstrapStateReq{
		token: session.Token,
		BootstrapConfig: sdk.BootstrapConfig{
			ThingID: chi.URLParam(r, "id"),
			State:   state,
		},
	}, nil
}

func decodeUpdateBootstrapCerts(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	var config sdk.BootstrapConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		return nil, err
	}
	config.ThingID = chi.URLParam(r, "id")

	return updateBootstrapCertReq{
		token:           session.Token,
		BootstrapConfig: config,
	}, nil
}

func decodeUpdateBootstrapConnections(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	return updateBootstrapConnReq{
		token: session.Token,
		BootstrapConfig: sdk.BootstrapConfig{
			ThingID:  chi.URLParam(r, "id"),
			Channels: r.PostForm["channelID"],
		},
	}, nil
}

func decodeListEntityRequest(_ context.Context, r *http.Request) (interface{}, error) {
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

	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}

	return listEntityReq{
		status:  status,
		page:    page,
		limit:   limit,
		Session: session,
	}, nil
}

func decodeListEntityByIDRequest(_ context.Context, r *http.Request) (interface{}, error) {
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

	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}

	return listEntityByIDReq{
		id:       chi.URLParam(r, "id"),
		page:     page,
		limit:    limit,
		relation: relation,
		Session:  session,
	}, nil
}

func decodeGetEntitiesRequest(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
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

	return getEntitiesReq{
		token:      session.Token,
		item:       item,
		page:       page,
		name:       name,
		domainID:   domainID,
		limit:      limit,
		permission: permission,
	}, nil
}

func decodeDomainLoginRequest(s *securecookie.SecureCookie) kithttp.DecodeRequestFunc {
	return func(_ context.Context, r *http.Request) (interface{}, error) {
		refreshTokenCookie, err := tokenFromCookie(r, refreshTokenKey)
		if err != nil {
			return nil, err
		}
		var refreshToken string
		if err := s.Decode(refreshTokenKey, refreshTokenCookie, &refreshToken); err != nil {
			return ui.Session{}, err
		}

		session, err := sessionFromHeader(r)
		if err != nil {
			return nil, err
		}
		session.LoginStatus = ui.DomainLoginStatus
		session.Token = refreshToken

		return domainLoginReq{
			Session: session,
			Login: sdk.Login{
				DomainID: r.FormValue("domainID"),
			},
		}, nil
	}
}

func decodeListDomainsRequest(_ context.Context, r *http.Request) (interface{}, error) {
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

	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}

	return listDomainsReq{
		status:  status,
		page:    page,
		limit:   limit,
		Session: session,
	}, nil
}

func decodeCreateDomainRequest(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
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

	return createDomainReq{
		token: session.Token,
		Domain: sdk.Domain{
			Name:     r.FormValue("name"),
			Alias:    r.FormValue("alias"),
			Tags:     tags,
			Metadata: meta,
		},
	}, nil
}

func decodeUpdateDomainRequest(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	var domain sdk.Domain
	if err := json.NewDecoder(r.Body).Decode(&domain); err != nil {
		return nil, err
	}
	domain.ID = chi.URLParam(r, "id")

	return updateDomainReq{
		token:  session.Token,
		Domain: domain,
	}, nil
}

func decodeUpdateDomainTagsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	var domain sdk.Domain
	if err := json.NewDecoder(r.Body).Decode(&domain); err != nil {
		return nil, err
	}
	domain.ID = chi.URLParam(r, "id")

	return updateDomainTagsReq{
		token:  session.Token,
		Domain: domain,
	}, nil
}

func decodeDomainStatusUpdate(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	return updateDomainStatusReq{
		token: session.Token,
		id:    r.PostFormValue("entityID"),
	}, nil
}

func decodeAssignMemberRequest(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	return assignMemberReq{
		token:    session.Token,
		domainID: chi.URLParam(r, "id"),
		UsersRelationRequest: sdk.UsersRelationRequest{
			UserIDs:  r.Form["userID"],
			Relation: r.Form.Get("relation"),
		},
	}, nil
}

func decodeViewMemberRequest(_ context.Context, r *http.Request) (interface{}, error) {
	identity, err := readStringQuery(r, identityKey, defKey)
	if err != nil {
		return nil, err
	}

	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}

	return viewMemberReq{
		Session:      session,
		userIdentity: identity,
	}, nil
}

func decodeSendInvitationRequest(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	return sendInvitationReq{
		token: session.Token,
		Invitation: sdk.Invitation{
			DomainID: r.PostFormValue("domainID"),
			UserID:   r.PostFormValue("userID"),
			Relation: r.PostFormValue("relation"),
		},
	}, nil
}

func decodeListInvitationsRequest(_ context.Context, r *http.Request) (interface{}, error) {
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

	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}

	return listInvitationsReq{
		Session:  session,
		domainID: domainID,
		page:     page,
		limit:    limit,
	}, nil
}

func decodeAcceptInvitationRequest(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
	if err != nil {
		return nil, err
	}
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	return acceptInvitationReq{
		token:    session.Token,
		domainID: r.Form.Get("domainID"),
	}, nil
}

func decodeDeleteInvitationRequest(_ context.Context, r *http.Request) (interface{}, error) {
	session, err := sessionFromHeader(r)
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

	return deleteInvitationReq{
		token:    session.Token,
		domain:   domain,
		domainID: r.Form.Get("domainID"),
		userID:   r.Form.Get("userID"),
	}, nil
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
		pageURL: r.URL.String(),
		err:     "Whoops! Page not found",
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

func readBoolQuery(r *http.Request, key string, def bool) (bool, error) {
	vals := r.URL.Query()[key]
	if len(vals) > 1 {
		return false, errInvalidQueryParams
	}

	if len(vals) == 0 {
		return def, nil
	}

	b, err := strconv.ParseBool(vals[0])
	if err != nil {
		return false, errors.Wrap(errInvalidQueryParams, err)
	}

	return b, nil
}

func tokenFromCookie(r *http.Request, cookie string) (string, error) {
	c, err := r.Cookie(cookie)
	if err != nil {
		return "", errors.Wrap(err, errInvalidCredentials)
	}

	return c.Value, nil
}

func sessionFromHeader(r *http.Request) (ui.Session, error) {
	session := r.Header.Get(sessionDetailsKey)
	var sessionDetails ui.Session
	if err := json.Unmarshal([]byte(session), &sessionDetails); err != nil {
		return ui.Session{}, err
	}

	return sessionDetails, nil
}

func AdminAuthMiddleware(prefix string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var err error
			defer func() {
				if err != nil {
					http.Redirect(w, r, fmt.Sprintf("%s/%s?error=%s", prefix, errorAPIEndpoint, url.QueryEscape(err.Error())), http.StatusSeeOther)
				}
			}()
			session, err := sessionFromHeader(r)
			if err != nil {
				http.Redirect(w, r, fmt.Sprintf("%s/%s", prefix, loginAPIEndpoint), http.StatusSeeOther)
				return
			}

			if session.User.Role != "admin" {
				err = errAuthorization
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func TokenMiddleware(prefix string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := sessionFromHeader(r)
			if err != nil {
				http.Redirect(w, r, fmt.Sprintf("%s/%s", prefix, loginAPIEndpoint), http.StatusSeeOther)
				return
			}

			// Parse the token without validation to get the expiration time
			token, _, err := new(jwt.Parser).ParseUnverified(session.Token, jwt.MapClaims{})
			if err != nil {
				http.Redirect(w, r, fmt.Sprintf("%s/%s?error=%s", prefix, errorAPIEndpoint, url.QueryEscape(err.Error())), http.StatusSeeOther)
				return
			}
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				if !claims.VerifyExpiresAt(time.Now().Unix(), true) {
					http.Redirect(w, r, fmt.Sprintf("%s/%s?referer_url=%s", prefix, tokenRefreshAPIEndpoint, url.QueryEscape(r.URL.String())), http.StatusSeeOther)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func AuthnMiddleware(prefix string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, err := sessionFromHeader(r)
			if err != nil {
				http.Redirect(w, r, fmt.Sprintf("%s/%s", prefix, loginAPIEndpoint), http.StatusSeeOther)
				return
			}

			token, _, err := new(jwt.Parser).ParseUnverified(session.Token, jwt.MapClaims{})
			if err != nil {
				http.Redirect(w, r, fmt.Sprintf("%s/%s?error=%s", prefix, errorAPIEndpoint, url.QueryEscape(err.Error())), http.StatusSeeOther)
				return
			}
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				if _, ok := claims["domain"]; !ok {
					http.Redirect(w, r, fmt.Sprintf("%s/%s", prefix, domainsAPIEndpoint), http.StatusSeeOther)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func DecryptCookieMiddleware(s *securecookie.SecureCookie, prefix string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var decryptedSessionCookie string
			sessionCookie, err := tokenFromCookie(r, sessionDetailsKey)
			if err != nil {
				http.Redirect(w, r, fmt.Sprintf("%s/%s", prefix, loginAPIEndpoint), http.StatusSeeOther)
				return
			}
			if err = s.Decode(sessionDetailsKey, sessionCookie, &decryptedSessionCookie); err != nil {
				err = errors.Wrap(err, errCookieDecryption)
				http.Redirect(w, r, fmt.Sprintf("%s/%s?error=%s", prefix, errorAPIEndpoint, url.QueryEscape(err.Error())), http.StatusSeeOther)
				return
			}

			r.Header.Set(sessionDetailsKey, decryptedSessionCookie)

			next.ServeHTTP(w, r)
		})
	}
}

func handleStaticFiles(m *chi.Mux) error {
	entries, err := ui.StaticFS.ReadDir(ui.StaticDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			fs := http.FileServer(http.FS(ui.StaticFS))
			m.Handle(fmt.Sprintf("/%s/*", entry.Name()), addPrefix(ui.StaticDir, fs))
		}
	}

	return nil
}

func addPrefix(prefix string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = fmt.Sprintf("%s%s", prefix, r.URL.Path)
		h.ServeHTTP(w, r)
	})
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

func encodeError(prefix string) kithttp.ErrorEncoder {
	return func(_ context.Context, err error, w http.ResponseWriter) {
		_, displayError := errors.Unwrap(err)

		switch {
		case errors.Contains(err, errInvalidCredentials),
			errors.Contains(err, errAuthentication),
			errors.Contains(err, ui.ErrTokenRefresh):
			w.Header().Set("Location", fmt.Sprintf("%s/login", prefix))
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
			errors.Contains(err, ui.ErrJSONMarshal),
			errors.Contains(err, ui.ErrFailedDashboardRetrieve):
			w.Header().Set("Location", fmt.Sprintf("%s/%s?error=%s", prefix, errorAPIEndpoint, url.QueryEscape(displayError.Error())))
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
}
