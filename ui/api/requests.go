// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"slices"
	"strings"
	"time"

	"github.com/absmach/magistrala-ui/ui"
	sdk "github.com/absmach/magistrala/pkg/sdk/go"
)

const (
	maxNameSize  = 1024
	maxLimitSize = 1000
)

var validAggregations = []string{"MAX", "MIN", "AVG", "SUM", "COUNT"}

type indexReq struct {
	ui.Session
}

func (req indexReq) validate() error {
	if req.AccessToken == "" {
		return errInvalidCredentials
	}
	return nil
}

type registerUserReq struct {
	sdk.User
}

func (req registerUserReq) validate() error {
	if req.User.Name == "" {
		return errMissingName
	}
	if req.User.Credentials.Identity == "" {
		return errMissingIdentity
	}
	if req.User.Credentials.Secret == "" {
		return errMissingSecret
	}
	return nil
}

type tokenReq struct {
	sdk.Login
}

func (req tokenReq) validate() error {
	if req.Identity == "" {
		return errMissingIdentity
	}
	if req.Secret == "" {
		return errMissingSecret
	}
	return nil
}

type secureTokenReq struct {
	ui.Session
}

func (req secureTokenReq) validate() error {
	if req.AccessToken == "" {
		return errInvalidCredentials
	}
	if req.RefreshToken == "" {
		return errMissingRefreshToken
	}
	return nil
}

type refreshTokenReq struct {
	ui.Session
	ref string
}

func (req refreshTokenReq) validate() error {
	if req.RefreshToken == "" {
		return errMissingRefreshToken
	}
	if req.ref == "" {
		return errMissingRef
	}
	return nil
}

type createUserReq struct {
	token string
	User  sdk.User `json:"user"`
}

func (req createUserReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.User.Credentials.Secret == "" {
		return errMissingSecret
	}
	if req.User.Credentials.Identity == "" {
		return errMissingIdentity
	}
	return nil
}

type createUsersReq struct {
	token string
	users []sdk.User
}

func (req createUsersReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	for _, user := range req.users {
		if user.Credentials.Secret == "" {
			return errMissingSecret
		}
		if user.Credentials.Identity == "" {
			return errMissingIdentity
		}
	}

	return nil
}

type listEntityReq struct {
	ui.Session
	status string
	page   uint64
	limit  uint64
}

func (req listEntityReq) validate() error {
	if req.AccessToken == "" {
		return errInvalidCredentials
	}
	if req.page == 0 {
		return errPageSize
	}
	if req.limit == 0 {
		return errLimitSize
	}
	return nil
}

type listEntityByIDReq struct {
	ui.Session
	id       string
	page     uint64
	limit    uint64
	relation string
}

func (req listEntityByIDReq) validate() error {
	if req.AccessToken == "" {
		return errInvalidCredentials
	}
	if req.id == "" {
		return errMissingUserID
	}
	if req.page == 0 {
		return errPageSize
	}
	if req.limit == 0 {
		return errLimitSize
	}
	return nil
}

type viewResourceReq struct {
	ui.Session
	id string
}

func (req viewResourceReq) validate() error {
	if req.AccessToken == "" {
		return errInvalidCredentials
	}
	if req.id == "" {
		return errMissingUserID
	}

	return nil
}

type updateUserReq struct {
	token string
	sdk.User
}

func (req updateUserReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.ID == "" {
		return errMissingUserID
	}
	if req.Name == "" && req.Metadata == nil {
		return errMissingValue
	}
	return nil
}

type updateUserTagsReq struct {
	token string
	sdk.User
}

func (req updateUserTagsReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.ID == "" {
		return errMissingUserID
	}
	return nil
}

type updateUserIdentityReq struct {
	token    string
	sdk.User `json:",inline"`
}

func (req updateUserIdentityReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.ID == "" {
		return errMissingUserID
	}
	if req.Credentials.Identity == "" {
		return errMissingIdentity
	}

	return nil
}

type updateUserStatusReq struct {
	token string
	id    string
}

func (req updateUserStatusReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.id == "" {
		return errMissingUserID
	}

	return nil
}

type updateUserRoleReq struct {
	token string
	sdk.User
}

func (req updateUserRoleReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.ID == "" {
		return errMissingUserID
	}
	if req.Role == "" {
		return errMissingRole
	}

	return nil
}

type showUpdatePasswordReq struct {
	ui.Session
}

type updateUserPasswordReq struct {
	token   string
	oldPass string
	newPass string
}

func (req updateUserPasswordReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.oldPass == "" {
		return errMissingSecret
	}
	if req.newPass == "" {
		return errMissingSecret
	}
	return nil
}

type passwordResetRequestReq struct {
	email string
}

func (req passwordResetRequestReq) validate() error {
	if req.email == "" {
		return errMissingEmail
	}
	return nil
}

type passwordResetReq struct {
	token           string
	password        string
	confirmPassword string
}

func (req passwordResetReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.password == "" {
		return errMissingPassword
	}
	if req.confirmPassword == "" {
		return errMissingConfirmPassword
	}
	if req.password != req.confirmPassword {
		return errInvalidResetPassword
	}
	return nil
}

type createThingReq struct {
	token string
	sdk.Thing
}

func (req createThingReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.Thing.Name == "" {
		return errMissingName
	}
	return nil
}

type updateThingReq struct {
	token string
	sdk.Thing
}

func (req updateThingReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.ID == "" {
		return errMissingThingID
	}
	if req.Name == "" && req.Metadata == nil {
		return errMissingValue
	}
	if len(req.Name) > maxNameSize {
		return errNameSize
	}
	return nil
}

type updateThingTagsReq struct {
	token string
	sdk.Thing
}

func (req updateThingTagsReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.ID == "" {
		return errMissingThingID
	}
	return nil
}

type updateThingSecretReq struct {
	token string
	sdk.Thing
}

func (req updateThingSecretReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.ID == "" {
		return errMissingThingID
	}
	if req.Credentials.Secret == "" {
		return errBearerKey
	}
	return nil
}

type updateThingStatusReq struct {
	token string
	id    string
}

func (req updateThingStatusReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.id == "" {
		return errMissingThingID
	}

	return nil
}

type createThingsReq struct {
	token  string
	things []sdk.Thing
}

func (req createThingsReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	return nil
}

type createChannelReq struct {
	token string
	sdk.Channel
}

func (req createChannelReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.Channel.Name == "" {
		return errMissingName
	}
	return nil
}

type createChannelsReq struct {
	token    string
	Channels []sdk.Channel
}

func (req createChannelsReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	for _, channel := range req.Channels {
		if channel.Name == "" {
			return errMissingName
		}
	}
	return nil
}

type updateChannelReq struct {
	token string
	sdk.Channel
}

func (req updateChannelReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.ID == "" {
		return errMissingChannelID
	}
	if req.Name == "" && req.Description == "" && req.Metadata == nil {
		return errMissingValue
	}
	if len(req.Name) > maxNameSize {
		return errNameSize
	}
	return nil
}

type connectThingReq struct {
	token     string
	thingID   string
	channelID string
	item      string
}

func (req connectThingReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.channelID == "" {
		return errMissingChannelID
	}
	if req.thingID == "" {
		return errMissingThingID
	}
	if req.item == "" {
		return errMissingItem
	}
	return nil
}

type shareThingReq struct {
	token string
	id    string
	sdk.UsersRelationRequest
}

func (req shareThingReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if len(req.UserIDs) == 0 {
		return errMissingUserID
	}
	if req.id == "" {
		return errMissingThingID
	}
	if req.Relation == "" {
		return errMissingRelation
	}
	return nil
}

type updateChannelStatusReq struct {
	token string
	id    string
}

func (req updateChannelStatusReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.id == "" {
		return errMissingChannelID
	}
	return nil
}

type createGroupReq struct {
	token string
	sdk.Group
}

func (req createGroupReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.Group.Name == "" {
		return errMissingName
	}

	return nil
}

type createGroupsReq struct {
	token  string
	Groups []sdk.Group
}

func (req createGroupsReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	for _, group := range req.Groups {
		if group.Name == "" {
			return errMissingName
		}
	}

	return nil
}

type updateGroupReq struct {
	token string
	sdk.Group
}

func (req updateGroupReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.ID == "" {
		return errMissingGroupID
	}
	if req.Name == "" && req.Description == "" && req.Metadata == nil {
		return errMissingValue
	}
	if len(req.Name) > maxNameSize {
		return errNameSize
	}
	return nil
}

type assignReq struct {
	token   string
	groupID string
	sdk.UsersRelationRequest
}

func (req assignReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}

	if req.groupID == "" {
		return errMissingGroupID
	}
	if len(req.UserIDs) == 0 {
		return errMissingUserID
	}
	if req.Relation == "" {
		return errMissingRelation
	}
	return nil
}

type updateGroupStatusReq struct {
	token string
	id    string
}

func (req updateGroupStatusReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.id == "" {
		return errMissingGroupID
	}
	return nil
}

type publishReq struct {
	thingKey  string
	channelID string
	Message   ui.Message
}

func (req publishReq) validate() error {
	if req.thingKey == "" {
		return errMissingThingKey
	}
	if req.channelID == "" {
		return errMissingChannel
	}
	return nil
}

type readMessagesReq struct {
	ui.Session
	channelID string
	thingKey  string
	page      uint64
	mpgm      sdk.MessagePageMetadata
}

func (req readMessagesReq) validate() error {
	if req.AccessToken == "" && req.thingKey == "" {
		return errInvalidCredentials
	}
	if req.channelID == "" {
		return errMissingChannelID
	}
	if req.page == 0 {
		return errPageSize
	}
	if req.mpgm.Limit < 1 || req.mpgm.Limit > maxLimitSize {
		return errLimitSize
	}

	if req.mpgm.Aggregation != "" {
		if req.mpgm.From == 0 {
			return errMissingFrom
		}

		if req.mpgm.To == 0 {
			return errMissingTo
		}

		if !slices.Contains(validAggregations, strings.ToUpper(req.mpgm.Aggregation)) {
			return errInvalidAggregation
		}

		if _, err := time.ParseDuration(req.mpgm.Interval); err != nil {
			return errInvalidInterval
		}
	}

	return nil
}

type bootstrapCommandReq struct {
	token   string
	command string
	id      string
}

func (req bootstrapCommandReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.id == "" {
		return errMissingConfigID
	}
	return nil
}

type updateBootstrapReq struct {
	token string
	sdk.BootstrapConfig
}

func (req updateBootstrapReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}

	if req.ThingID == "" {
		return errMissingConfigID
	}
	return nil
}

type deleteBootstrapReq struct {
	token string
	id    string
}

func (req deleteBootstrapReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.id == "" {
		return errMissingConfigID
	}
	return nil
}

type updateBootstrapStateReq struct {
	token string
	sdk.BootstrapConfig
}

func (req updateBootstrapStateReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.ThingID == "" {
		return errMissingConfigID
	}
	return nil
}

type updateBootstrapCertReq struct {
	token string
	sdk.BootstrapConfig
}

func (req updateBootstrapCertReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.ThingID == "" {
		return errMissingThingID
	}
	return nil
}

type updateBootstrapConnReq struct {
	token string
	sdk.BootstrapConfig
}

func (req updateBootstrapConnReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.ThingID == "" {
		return errMissingConfigID
	}
	return nil
}

type createBootstrapReq struct {
	token string
	sdk.BootstrapConfig
}

func (req createBootstrapReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.ExternalID == "" {
		return errMissingExternalID
	}
	if req.ExternalKey == "" {
		return errMissingExternalKey
	}
	return nil
}

type getEntitiesReq struct {
	token      string
	page       uint64
	limit      uint64
	item       string
	name       string
	domainID   string
	permission string
}

func (req getEntitiesReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.page == 0 {
		return errPageSize
	}
	if req.item == "" {
		return errMissingItem
	}
	if req.limit == 0 {
		return errLimitSize
	}
	return nil
}

type errorReq struct {
	pageURL string
	err     string
}

func (req errorReq) validate() error {
	if req.err == "" {
		return errMissingError
	}
	return nil
}

type addUserToChannelReq struct {
	token     string
	ChannelID string `json:"channel_id"`
	sdk.UsersRelationRequest
}

func (req addUserToChannelReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.ChannelID == "" {
		return errMissingChannelID
	}
	if len(req.UserIDs) == 0 {
		return errMissingUserID
	}
	if req.Relation == "" {
		return errMissingRelation
	}
	return nil
}

type addUserGroupToChannelReq struct {
	token     string
	channelID string
	item      string
	sdk.UserGroupsRequest
}

func (req addUserGroupToChannelReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.channelID == "" {
		return errMissingChannelID
	}
	if len(req.UserGroupIDs) == 0 {
		return errMissingGroupID
	}
	if req.item == "" {
		return errMissingItem
	}
	return nil
}

type domainLoginReq struct {
	ui.Session
	sdk.Login
}

func (req domainLoginReq) validate() error {
	if req.AccessToken == "" {
		return errAuthentication
	}
	if req.DomainID == "" {
		return errMissingDomainID
	}
	return nil
}

type listDomainsReq struct {
	ui.Session
	status string
	page   uint64
	limit  uint64
}

func (req listDomainsReq) validate() error {
	if req.Token.AccessToken == "" {
		return errAuthentication
	}
	if req.page == 0 {
		return errPageSize
	}
	if req.limit == 0 {
		return errLimitSize
	}
	return nil
}

type createDomainReq struct {
	token string
	sdk.Domain
}

func (req createDomainReq) validate() error {
	if req.token == "" {
		return errAuthentication
	}
	if req.Name == "" {
		return errMissingName
	}
	return nil
}

type updateDomainReq struct {
	token string
	sdk.Domain
}

func (req updateDomainReq) validate() error {
	if req.token == "" {
		return errAuthentication
	}
	if req.ID == "" {
		return errMissingDomainID
	}
	if req.Name == "" && req.Alias == "" && req.Metadata == nil {
		return errMissingValue
	}
	return nil
}

type updateDomainTagsReq struct {
	token string
	sdk.Domain
}

func (req updateDomainTagsReq) validate() error {
	if req.token == "" {
		return errAuthentication
	}
	if req.ID == "" {
		return errMissingDomainID
	}
	return nil
}

type updateDomainStatusReq struct {
	token string
	id    string
}

func (req updateDomainStatusReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.id == "" {
		return errMissingDomainID
	}

	return nil
}

type assignMemberReq struct {
	token    string
	domainID string
	sdk.UsersRelationRequest
}

func (req assignMemberReq) validate() error {
	if req.token == "" {
		return errAuthentication
	}
	if req.domainID == "" {
		return errMissingDomainID
	}
	if len(req.UserIDs) == 0 {
		return errMissingUserID
	}
	if req.Relation == "" {
		return errMissingRelation
	}
	return nil
}

type viewMemberReq struct {
	ui.Session
	userIdentity string
}

func (req viewMemberReq) validate() error {
	if req.AccessToken == "" {
		return errAuthentication
	}
	if req.userIdentity == "" {
		return errMissingIdentity
	}
	return nil
}

type sendInvitationReq struct {
	token string
	sdk.Invitation
}

func (req sendInvitationReq) validate() error {
	if req.token == "" {
		return errAuthentication
	}
	if req.DomainID == "" {
		return errMissingDomainID
	}
	if req.UserID == "" {
		return errMissingUserID
	}
	if req.Relation == "" {
		return errMissingRelation
	}

	return nil
}

type acceptInvitationReq struct {
	token    string
	domainID string
}

func (req acceptInvitationReq) validate() error {
	if req.token == "" {
		return errAuthentication
	}
	if req.domainID == "" {
		return errMissingDomainID
	}

	return nil
}

type deleteInvitationReq struct {
	token    string
	domain   string
	domainID string
	userID   string
}

func (req deleteInvitationReq) validate() error {
	if req.token == "" {
		return errAuthentication
	}
	if req.domainID == "" {
		return errMissingDomainID
	}
	if req.userID == "" {
		return errMissingUserID
	}

	return nil
}

type listInvitationsReq struct {
	ui.Session
	domainID string
	page     uint64
	limit    uint64
}

func (req listInvitationsReq) validate() error {
	if req.AccessToken == "" {
		return errAuthentication
	}
	if req.page == 0 {
		return errPageSize
	}
	if req.limit == 0 {
		return errLimitSize
	}

	return nil
}

type viewDashboardReq struct {
	ui.Session
	DashboardID string `json:"dashboard_id"`
}

func (req viewDashboardReq) validate() error {
	if req.AccessToken == "" {
		return errInvalidCredentials
	}
	return nil
}

type createDashboardReq struct {
	token       string
	Name        string `json:"name"`
	Description string `json:"description"`
	Layout      string `json:"layout"`
}

func (req createDashboardReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	return nil
}

type listDashboardsReq struct {
	token string
	page  uint64
	limit uint64
}

func (req listDashboardsReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	if req.page == 0 {
		return errPageSize
	}
	return nil
}

type dashboardsReq struct {
	ui.Session
}

func (req dashboardsReq) validate() error {
	return nil
}

type updateDashboardReq struct {
	token       string
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Metadata    string `json:"metadata"`
	Layout      string `json:"layout"`
}

func (req updateDashboardReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	return nil
}

type deleteDashboardReq struct {
	token string
	ID    string `json:"id"`
}

func (req deleteDashboardReq) validate() error {
	if req.token == "" {
		return errInvalidCredentials
	}
	return nil
}
