// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"github.com/mainflux/mainflux/pkg/messaging"
	sdk "github.com/mainflux/mainflux/pkg/sdk/go"
)

const maxNameSize = 1024

type indexReq struct {
	token string
}

func (req indexReq) validate() error {
	if req.token == "" {
		return errAuthorization
	}
	return nil
}

type tokenReq struct {
	Identity string `json:"identity"`
	Secret   string `json:"secret"`
}

func (req tokenReq) validate() error {
	if req.Identity == "" {
		return errMalformedEntity
	}
	if req.Secret == "" {
		return errMalformedEntity
	}
	return nil
}

type refreshTokenReq struct {
	refreshToken string
	ref          string
}

func (req refreshTokenReq) validate() error {
	if req.refreshToken == "" {
		return errMalformedEntity
	}
	if req.ref == "" {
		return errMalformedEntity
	}
	return nil
}

type createUserReq struct {
	token string
	User  sdk.User `json:"user"`
}

func (req createUserReq) validate() error {
	if req.token == "" {
		return errAuthorization
	}
	if req.User.Credentials.Secret == "" || req.User.Credentials.Identity == "" {
		return errMalformedEntity
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
		return errAuthorization
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
		return errAuthorization
	}
	if req.page == 0 {
		return errMalformedEntity
	}
	if req.limit == 0 {
		return errMalformedEntity
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
		return errAuthorization
	}
	if req.id == "" {
		return errMalformedEntity
	}
	if req.page == 0 {
		return errMalformedEntity
	}
	if req.limit == 0 {
		return errMalformedEntity
	}
	return nil
}

type viewResourceReq struct {
	token string
	id    string
}

func (req viewResourceReq) validate() error {
	if req.token == "" {
		return errAuthorization
	}

	if req.id == "" {
		return errMalformedEntity
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
		return errAuthorization
	}
	if req.id == "" {
		return errMalformedEntity
	}
	if req.Name == "" && req.Metadata == nil {
		return errMalformedEntity
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
		return errAuthorization
	}
	if req.id == "" {
		return errMalformedEntity
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
		return errAuthorization
	}
	if req.id == "" {
		return errMalformedEntity
	}
	if req.Identity == "" {
		return errMalformedEntity
	}

	return nil
}

type updateUserStatusReq struct {
	token  string
	UserID string `json:"userId,omitempty"`
}

func (req updateUserStatusReq) validate() error {
	if req.token == "" {
		return errAuthorization
	}
	if req.UserID == "" {
		return errMalformedEntity
	}

	return nil
}

type showUpdatePasswordReq struct {
	token string
}

func (req showUpdatePasswordReq) validate() error {
	if req.token == "" {
		return errAuthorization
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
		return errAuthorization
	}
	if req.OldPass == "" {
		return errMalformedEntity
	}
	if req.NewPass == "" {
		return errMalformedEntity
	}
	return nil
}

type passwordResetRequestReq struct {
	Email string `json:"email"`
}

func (req passwordResetRequestReq) validate() error {
	if req.Email == "" {
		return errMalformedEntity
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
		return errAuthorization
	}
	if req.Password == "" {
		return errMalformedEntity
	}
	if req.ConfirmPassword == "" {
		return errMalformedEntity
	}
	if req.Password != req.ConfirmPassword {
		return errMalformedEntity
	}
	return nil
}

type createThingReq struct {
	token string
	Thing sdk.Thing `json:"thing"`
}

func (req createThingReq) validate() error {
	if req.token == "" {
		return errAuthorization
	}
	if req.Thing.Name == "" {
		return errMalformedEntity
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
		return errAuthorization
	}
	if req.id == "" {
		return errMalformedEntity
	}
	if req.Name == "" && req.Metadata == nil {
		return errMalformedEntity
	}
	if len(req.Name) > maxNameSize {
		return errMalformedEntity
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
		return errAuthorization
	}
	if req.id == "" {
		return errMalformedEntity
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
		return errAuthorization
	}
	if req.id == "" {
		return errMalformedEntity
	}
	if req.Secret == "" {
		return errMalformedEntity
	}

	return nil
}

type updateThingStatusReq struct {
	token   string
	ThingID string `json:"thingID,omitempty"`
}

func (req updateThingStatusReq) validate() error {
	if req.token == "" {
		return errAuthorization
	}
	if req.ThingID == "" {
		return errMalformedEntity
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
		return errAuthorization
	}
	if req.id == "" {
		return errMalformedEntity
	}
	if req.Owner == "" {
		return errMalformedEntity
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
		return errAuthorization
	}

	return nil
}

type createChannelReq struct {
	token   string
	Channel sdk.Channel `json:"channel"`
}

func (req createChannelReq) validate() error {
	if req.token == "" {
		return errAuthorization
	}
	if req.Channel.Name == "" {
		return errMalformedEntity
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
		return errAuthorization
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
		return errAuthorization
	}
	if req.id == "" {
		return errMalformedEntity
	}
	if req.Name == "" && req.Description == "" && req.Metadata == nil {
		return errMalformedEntity
	}
	if len(req.Name) > maxNameSize {
		return errMalformedEntity
	}

	return nil
}

type connectThingReq struct {
	token   string
	ThingID string `json:"thingID,omitempty"`
	ChanID  string `json:"chanID,omitempty"`
}

func (req connectThingReq) validate() error {
	if req.token == "" {
		return errAuthorization
	}
	if req.ChanID == "" {
		return errMalformedEntity
	}
	if req.ThingID == "" {
		return errMalformedEntity
	}
	return nil
}

type shareThingReq struct {
	token    string
	ThingID  string `json:"thingID,omitempty"`
	UserID   string `json:"userID,omitempty"`
	Relation string `json:"relation,omitempty"`
}

func (req shareThingReq) validate() error {
	if req.token == "" {
		return errAuthorization
	}
	if req.UserID == "" {
		return errMalformedEntity
	}
	if req.ThingID == "" {
		return errMalformedEntity
	}
	if req.Relation == "" {
		return errMalformedEntity
	}
	return nil
}

type updateChannelStatusReq struct {
	token     string
	ChannelID string `json:"channelID,omitempty"`
}

func (req updateChannelStatusReq) validate() error {
	if req.token == "" {
		return errAuthorization
	}
	if req.ChannelID == "" {
		return errMalformedEntity
	}

	return nil
}

type createGroupReq struct {
	token string
	Group sdk.Group
}

func (req createGroupReq) validate() error {
	if req.token == "" {
		return errAuthorization
	}
	if req.Group.Name == "" {
		return errMalformedEntity
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
		return errAuthorization
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
		return errAuthorization
	}
	if req.id == "" {
		return errMalformedEntity
	}
	if req.Name == "" && req.Description == "" && req.ParentID == "" && req.Metadata == nil {
		return errMalformedEntity
	}
	if len(req.Name) > maxNameSize {
		return errMalformedEntity
	}

	return nil
}

type assignReq struct {
	token    string
	GroupID  string `json:"groupID"`
	UserID   string `json:"userID"`
	Relation string `json:"relation"`
}

func (req assignReq) validate() error {
	if req.token == "" {
		return errAuthorization
	}

	if req.GroupID == "" {
		return errMalformedEntity
	}
	if req.UserID == "" {
		return errMalformedEntity
	}
	if req.Relation == "" {
		return errMalformedEntity
	}

	return nil
}

type updateGroupStatusReq struct {
	token   string
	GroupID string `json:"groupId"`
}

func (req updateGroupStatusReq) validate() error {
	if req.token == "" {
		return errAuthorization
	}
	if req.GroupID == "" {
		return errMalformedEntity
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
		return errAuthorization
	}

	if req.thingKey == "" {
		return errMalformedEntity
	}
	if req.Msg.Channel == "" {
		return errMalformedEntity
	}
	if req.Msg.Payload == nil {
		return errMalformedEntity
	}
	return nil
}

type readMessageReq struct {
	token    string
	ChanID   string `json:"chan_id,omitempty"`
	ThingKey string `json:"thing_key,omitempty"`
	Page  uint64
	Limit uint64
}

func (req readMessageReq) validate() error {
	if req.token == "" {
		return errAuthorization
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
		return errAuthorization
	}

	if req.id == "" {
		return errMalformedEntity
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
		return errAuthorization
	}

	if req.id == "" {
		return errMalformedEntity
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
		return errAuthorization
	}

	if req.thingID == "" {
		return errMalformedEntity
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
		return errAuthorization
	}

	if req.id == "" {
		return errMalformedEntity
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
		return errAuthorization
	}

	if req.ExternalID == "" {
		return errMalformedEntity
	}

	if req.ExternalKey == "" {
		return errMalformedEntity
	}

	return nil
}

type getEntitiesReq struct {
	token string
	Page  uint64 `json:"page"`
	Limit uint64 `json:"limit"`
	Item  string `json:"item"`
	Name  string `json:"name"`
}

func (req getEntitiesReq) validate() error {
	if req.token == "" {
		return errAuthorization
	}

	if req.Page == 0 {
		return errMalformedEntity
	}
	if req.Item == "" {
		return errMalformedEntity
	}

	if req.Limit == 0 {
		return errMalformedEntity
	}
	return nil
}

type errorReq struct {
	err string
}

func (req errorReq) validate() error {
	if req.err == "" {
		return errMalformedEntity
	}
	return nil
}

type addUserToChannelReq struct {
	token     string
	ChannelID string `json:"channelID"`
	UserID    string `json:"userID"`
	Relation  string `json:"relation"`
}

func (req addUserToChannelReq) validate() error {
	if req.token == "" {
		return errAuthorization
	}
	if req.ChannelID == "" {
		return errMalformedEntity
	}
	if req.UserID == "" {
		return errMalformedEntity
	}
	if req.Relation == "" {
		return errMalformedEntity
	}
	return nil
}

type addUserGroupToChannelReq struct {
	token     string
	GroupID   string `json:"groupID"`
	ChannelID string `json:"channelID"`
}

func (req addUserGroupToChannelReq) validate() error {
	if req.token == "" {
		return errAuthorization
	}
	if req.ChannelID == "" {
		return errMalformedEntity
	}
	if req.GroupID == "" {
		return errMalformedEntity
	}
	return nil
}
