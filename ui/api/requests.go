// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"github.com/mainflux/mainflux/pkg/messaging"
	sdk "github.com/mainflux/mainflux/pkg/sdk/go"
	"github.com/ultravioletrs/mainflux-ui/ui"
)

const maxNameSize = 1024

type indexReq struct {
	token string
}

func (req indexReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	return nil
}

type tokenReq struct {
	Identity string `json:"identity"`
	Secret   string `json:"secret"`
}

func (req tokenReq) validate() error {
	if req.Identity == "" {
		return ui.ErrMalformedEntity
	}
	if req.Secret == "" {
		return ui.ErrMalformedEntity
	}
	return nil
}

type refreshTokenReq struct {
	refreshToken string
	ref          string
}

func (req refreshTokenReq) validate() error {
	if req.refreshToken == "" {
		return ui.ErrMalformedEntity
	}
	if req.ref == "" {
		return ui.ErrMalformedEntity
	}
	return nil
}

type createUserReq struct {
	token string
	User  sdk.User `json:"user"`
}

func (req createUserReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.User.Credentials.Secret == "" || req.User.Credentials.Identity == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type createUsersReq struct {
	token     string
	Names     []string               `json:"names"`
	Emails    []string               `json:"emails"`
	Passwords []string               `json:"passwords"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

func (req createUsersReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	return nil
}

type listEntityReq struct {
	token string
	page  uint64
	limit uint64
}

func (req listEntityReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.page == 0 {
		return ui.ErrMalformedEntity
	}
	if req.limit == 0 {
		return ui.ErrMalformedEntity
	}
	return nil
}

type listEntityByIDReq struct {
	token string
	id    string
	page  uint64
	limit uint64
}

func (req listEntityByIDReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.id == "" {
		return ui.ErrMalformedEntity
	}
	if req.page == 0 {
		return ui.ErrMalformedEntity
	}
	if req.limit == 0 {
		return ui.ErrMalformedEntity
	}
	return nil
}

type viewResourceReq struct {
	token string
	id    string
}

func (req viewResourceReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	if req.id == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type updateUserReq struct {
	token    string
	id       string
	Name     string                 `json:"name,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

func (req updateUserReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.id == "" {
		return ui.ErrMalformedEntity
	}
	if req.Name == "" && req.Metadata == nil {
		return ui.ErrMalformedEntity
	}
	return nil
}

type updateUserTagsReq struct {
	token string
	id    string
	Tags  []string `json:"tags,omitempty"`
}

func (req updateUserTagsReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.id == "" {
		return ui.ErrMalformedEntity
	}
	return nil
}

type updateUserIdentityReq struct {
	token    string
	id       string
	Identity string `json:"identity"`
}

func (req updateUserIdentityReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.id == "" {
		return ui.ErrMalformedEntity
	}
	if req.Identity == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type updateUserStatusReq struct {
	token  string
	UserID string `json:"userId,omitempty"`
}

func (req updateUserStatusReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.UserID == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type updateUserPasswordReq struct {
	token   string
	OldPass string `json:"oldpass"`
	NewPass string `json:"newpass"`
}

func (req updateUserPasswordReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.OldPass == "" {
		return ui.ErrMalformedEntity
	}
	if req.NewPass == "" {
		return ui.ErrMalformedEntity
	}
	return nil
}

type passwordResetRequestReq struct {
	Email string `json:"email"`
}

func (req passwordResetRequestReq) validate() error {
	if req.Email == "" {
		return ui.ErrMalformedEntity
	}
	return nil
}

type passwordResetReq struct {
	token           string
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirm_password"`
}

func (req passwordResetReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.Password == "" {
		return ui.ErrMalformedEntity
	}
	if req.ConfirmPassword == "" {
		return ui.ErrMalformedEntity
	}
	if req.Password != req.ConfirmPassword {
		return ui.ErrInvalidResetPass
	}
	return nil
}

type createThingReq struct {
	token string
	Thing sdk.Thing `json:"thing"`
}

func (req createThingReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.Thing.Name == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type updateThingReq struct {
	token    string
	id       string
	Name     string                 `json:"name,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

func (req updateThingReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.id == "" {
		return ui.ErrMalformedEntity
	}
	if req.Name == "" && req.Metadata == nil {
		return ui.ErrMalformedEntity
	}
	if len(req.Name) > maxNameSize {
		return ui.ErrMalformedEntity
	}

	return nil
}

type updateThingTagsReq struct {
	token string
	id    string
	Tags  []string `json:"tags,omitempty"`
}

func (req updateThingTagsReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.id == "" {
		return ui.ErrMalformedEntity
	}
	return nil
}

type updateThingSecretReq struct {
	token  string
	id     string
	Secret string `json:"secret"`
}

func (req updateThingSecretReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.id == "" {
		return ui.ErrMalformedEntity
	}
	if req.Secret == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type updateThingStatusReq struct {
	token   string
	ThingID string `json:"thingID,omitempty"`
}

func (req updateThingStatusReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.ThingID == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type updateThingOwnerReq struct {
	token string
	id    string
	Owner string `json:"owner,omitempty"`
}

func (req updateThingOwnerReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.id == "" {
		return ui.ErrMalformedEntity
	}
	if req.Owner == "" {
		return ui.ErrMalformedEntity
	}
	return nil
}

type createThingsReq struct {
	token     string
	Names     []string                 `json:"names,omitempty"`
	Metadatas []map[string]interface{} `json:"metadatas,omitempty"`
}

func (req createThingsReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	return nil
}

type createChannelReq struct {
	token   string
	Channel sdk.Channel `json:"channel"`
}

func (req createChannelReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.Channel.Name == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type createChannelsReq struct {
	token     string
	Names     []string                 `json:"names"`
	IDs       []string                 `json:"ids,omitempty"`
	Metadatas []map[string]interface{} `json:"metadatas,omitempty"`
}

func (req createChannelsReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	return nil
}

type updateChannelReq struct {
	token       string
	id          string
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

func (req updateChannelReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.id == "" {
		return ui.ErrMalformedEntity
	}
	if req.Name == "" && req.Description == "" && req.Metadata == nil {
		return ui.ErrMalformedEntity
	}
	if len(req.Name) > maxNameSize {
		return ui.ErrMalformedEntity
	}

	return nil
}

type connectThingReq struct {
	token   string
	ConnIDs sdk.ConnectionIDs
}

func (req connectThingReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if len(req.ConnIDs.ChannelIDs) == 0 {
		return ui.ErrMalformedEntity
	}
	if len(req.ConnIDs.ThingIDs) == 0 {
		return ui.ErrMalformedEntity
	}
	if len(req.ConnIDs.Actions) == 0 {
		return ui.ErrMalformedEntity
	}
	return nil
}

type shareThingReq struct {
	token   string
	UserID  string   `json:"user_id"`
	ChanID  string   `json:"channel_id"`
	Actions []string `json:"actions"`
}

func (req shareThingReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.UserID == "" {
		return ui.ErrMalformedEntity
	}
	if req.ChanID == "" {
		return ui.ErrMalformedEntity
	}
	if len(req.Actions) == 0 {
		return ui.ErrMalformedEntity
	}
	return nil
}

type connectChannelReq struct {
	token   string
	ConnIDs sdk.ConnectionIDs `json:"connection_ids"`
}

func (req connectChannelReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if len(req.ConnIDs.ChannelIDs) == 0 {
		return ui.ErrMalformedEntity
	}
	if len(req.ConnIDs.ThingIDs) == 0 {
		return ui.ErrMalformedEntity
	}
	if len(req.ConnIDs.Actions) == 0 {
		return ui.ErrMalformedEntity
	}

	return nil
}

type connectReq struct {
	token   string
	ConnIDs sdk.ConnectionIDs `json:"connection_ids"`
}

func (req connectReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if len(req.ConnIDs.ChannelIDs) == 0 {
		return ui.ErrMalformedEntity
	}
	if len(req.ConnIDs.ThingIDs) == 0 {
		return ui.ErrMalformedEntity
	}
	if len(req.ConnIDs.Actions) == 0 {
		return ui.ErrMalformedEntity
	}

	return nil
}

type disconnectThingReq struct {
	token   string
	ChanID  string `json:"chan_id,omitempty"`
	ThingID string `json:"thing_id,omitempty"`
}

func (req disconnectThingReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	if req.ChanID == "" {
		return ui.ErrMalformedEntity
	}
	if req.ThingID == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type disconnectChannelReq struct {
	token   string
	ChanID  string `json:"chan_id,omitempty"`
	ThingID string `json:"thing_id,omitempty"`
}

func (req disconnectChannelReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	if req.ChanID == "" {
		return ui.ErrMalformedEntity
	}
	if req.ThingID == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type disconnectReq struct {
	token   string
	ConnIDs sdk.ConnectionIDs `json:"connection_ids"`
}

func (req disconnectReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if len(req.ConnIDs.ChannelIDs) == 0 {
		return ui.ErrMalformedEntity
	}
	if len(req.ConnIDs.ThingIDs) == 0 {
		return ui.ErrMalformedEntity
	}
	if len(req.ConnIDs.Actions) == 0 {
		return ui.ErrMalformedEntity
	}

	return nil
}

type updateChannelStatusReq struct {
	token     string
	ChannelID string `json:"channelID,omitempty"`
}

func (req updateChannelStatusReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.ChannelID == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type addThingsPolicyReq struct {
	token  string
	Policy sdk.Policy `json:"policy,omitempty"`
}

func (req addThingsPolicyReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.Policy.Subject == "" {
		return ui.ErrMalformedEntity
	}
	if req.Policy.Object == "" {
		return ui.ErrMalformedEntity
	}
	if len(req.Policy.Actions) == 0 {
		return ui.ErrMalformedEntity
	}

	return nil
}

type deleteThingsPolicyReq struct {
	token  string
	Policy sdk.Policy `json:"policy,omitempty"`
}

func (req deleteThingsPolicyReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.Policy.Subject == "" {
		return ui.ErrMalformedEntity
	}
	if req.Policy.Object == "" {
		return ui.ErrMalformedEntity
	}
	if len(req.Policy.Actions) == 0 {
		return ui.ErrMalformedEntity
	}

	return nil
}

type createGroupReq struct {
	token string
	Group sdk.Group
}

func (req createGroupReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.Group.Name == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type createGroupsReq struct {
	token        string
	Names        []string                 `json:"names,omitempty"`
	Descriptions []string                 `json:"descriptions,omitempty"`
	Metadatas    []map[string]interface{} `json:"metadatas,omitempty"`
}

func (req createGroupsReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	return nil
}

type updateGroupReq struct {
	token       string
	id          string
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	ParentID    string                 `json:"parent_id,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

func (req updateGroupReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.id == "" {
		return ui.ErrMalformedEntity
	}
	if req.Name == "" && req.Description == "" && req.ParentID == "" && req.Metadata == nil {
		return ui.ErrMalformedEntity
	}
	if len(req.Name) > maxNameSize {
		return ui.ErrMalformedEntity
	}

	return nil
}

type assignReq struct {
	token    string
	groupID  string
	Type     []string `json:"Type,omitempty"`
	MemberID string   `json:"memberID,omitempty"`
}

func (req assignReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	if req.groupID == "" {
		return ui.ErrMalformedEntity
	}
	if req.MemberID == "" {
		return ui.ErrMalformedEntity
	}
	if len(req.Type) == 0 {
		return ui.ErrMalformedEntity
	}

	return nil
}

type unassignReq struct {
	token    string
	groupID  string
	MemberID string `json:"memberId,omitempty"`
}

func (req unassignReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	if req.groupID == "" {
		return ui.ErrMalformedEntity
	}
	if req.MemberID == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type updateGroupStatusReq struct {
	token   string
	GroupID string `json:"groupId,omitempty"`
}

func (req updateGroupStatusReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.GroupID == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type addPolicyReq struct {
	token  string
	Policy sdk.Policy `json:"policy,omitempty"`
}

func (req addPolicyReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.Policy.Subject == "" {
		return ui.ErrMalformedEntity
	}
	if req.Policy.Object == "" {
		return ui.ErrMalformedEntity
	}
	if len(req.Policy.Actions) == 0 {
		return ui.ErrMalformedEntity
	}

	return nil
}

type updatePolicyReq struct {
	token  string
	Policy sdk.Policy `json:"policy,omitempty"`
}

func (req updatePolicyReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.Policy.Subject == "" {
		return ui.ErrMalformedEntity
	}
	if req.Policy.Object == "" {
		return ui.ErrMalformedEntity
	}
	if len(req.Policy.Actions) == 0 {
		return ui.ErrMalformedEntity
	}
	return nil
}

type deletePolicyReq struct {
	token  string
	Policy sdk.Policy `json:"policy,omitempty"`
}

func (req deletePolicyReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.Policy.Subject == "" {
		return ui.ErrMalformedEntity
	}
	if req.Policy.Object == "" {
		return ui.ErrMalformedEntity
	}
	if len(req.Policy.Actions) == 0 {
		return ui.ErrMalformedEntity
	}

	return nil
}

type publishReq struct {
	thingKey string
	token    string
	Msg      *messaging.Message
}

func (req publishReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	if req.thingKey == "" {
		return ui.ErrMalformedEntity
	}
	if req.Msg.Channel == "" {
		return ui.ErrMalformedEntity
	}
	if req.Msg.Payload == nil {
		return ui.ErrMalformedEntity
	}
	return nil
}

type readMessageReq struct {
	token string
}

func (req readMessageReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	return nil
}

type wsConnectionReq struct {
	token    string
	ChanID   string `json:"chan_id,omitempty"`
	ThingKey string `json:"thing_key,omitempty"`
}

func (req wsConnectionReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	if req.ChanID == "" {
		return ui.ErrMalformedEntity
	}
	if req.ThingKey == "" {
		return ui.ErrMalformedEntity
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
		return ui.ErrUnauthorizedAccess
	}

	if req.id == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type updateBootstrapReq struct {
	token   string
	id      string
	Name    string `json:"name"`
	Content string `json:"content"`
}

func (req updateBootstrapReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	if req.id == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type updateBootstrapCertReq struct {
	token      string
	thingID    string
	ClientCert string `json:"clientCert"`
	ClientKey  string `json:"clientKey"`
	CACert     string `json:"CAcert"`
}

func (req updateBootstrapCertReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	if req.thingID == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type updateBootstrapConnReq struct {
	token    string
	id       string
	Channels []string `json:"channels"`
}

func (req updateBootstrapConnReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	if req.id == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type createBootstrapReq struct {
	token       string
	ThingID     string   `json:"thingID"`
	ExternalID  string   `json:"externalID"`
	ExternalKey string   `json:"externalKey"`
	Channels    []string `json:"channels"`
	Name        string   `json:"name"`
	Content     string   `json:"content"`
	ClientCert  string   `json:"clientCert"`
	ClientKey   string   `json:"clientKey"`
	CACert      string   `json:"CAcert"`
}

func (req createBootstrapReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	if req.ExternalID == "" {
		return ui.ErrMalformedEntity
	}

	if req.ExternalKey == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}
