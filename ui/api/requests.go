// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"github.com/mainflux/mainflux/pkg/messaging"
	"github.com/ultravioletrs/mainflux-ui/ui"
)

const maxNameSize = 1024

type indexReq struct {
	token string
}

type createThingReq struct {
	token    string
	Name     string                 `json:"name,omitempty"`
	Key      string                 `json:"key,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

func (req createThingReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	if len(req.Name) > maxNameSize {
		return ui.ErrMalformedEntity
	}

	return nil
}

type createThingsReq struct {
	token     string
	Names     []string                 `json:"names,omitempty"`
	Keys      []string                 `json:"keys,omitempty"`
	Metadatas []map[string]interface{} `json:"metadata,omitempty"`
}

func (req createThingsReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	for _, name := range req.Names {
		if len(name) > maxNameSize {
			return ui.ErrMalformedEntity
		}
	}
	return nil
}

type listThingsReq struct {
	token string
}

func (req listThingsReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
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

	if len(req.Name) > maxNameSize {
		return ui.ErrMalformedEntity
	}

	return nil
}

type createChannelReq struct {
	token    string
	Name     string                 `json:"name,omitempty"`
	ID       string                 `json:"key,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

func (req createChannelReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	if len(req.Name) > maxNameSize {
		return ui.ErrMalformedEntity
	}

	return nil
}

type createChannelsReq struct {
	token     string
	Names     []string                 `json:"name,omitempty"`
	IDs       []string                 `json:"id,omitempty"`
	Metadatas []map[string]interface{} `json:"metadata,omitempty"`
}

func (req createChannelsReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	for _, name := range req.Names {
		if len(name) > maxNameSize {
			return ui.ErrMalformedEntity
		}
	}
	return nil
}

type updateChannelReq struct {
	token    string
	id       string
	Name     string                 `json:"name,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

func (req updateChannelReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.id == "" {
		return ui.ErrMalformedEntity
	}

	if len(req.Name) > maxNameSize {
		return ui.ErrMalformedEntity
	}

	return nil
}

type listChannelsReq struct {
	token string
}

func (req listChannelsReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	return nil
}

type createGroupsReq struct {
	token       string
	ID          string                 `json:"id,omitempty"`
	Name        string                 `json:"name,omitempty"`
	Description string                 `json:"description,omitempty"`
	ParentID    string                 `json:"parent_id,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

func (req createGroupsReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	if len(req.Name) > maxNameSize {
		return ui.ErrMalformedEntity
	}

	return nil
}

type listGroupsReq struct {
	token string
}

type loginReq struct {
}

func (req listGroupsReq) validate() error {
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
		return ui.ErrMalformedEntity
	}

	if len(req.Name) > maxNameSize {
		return ui.ErrMalformedEntity
	}

	return nil
}

type connectThingReq struct {
	token   string
	ChanID  string `json:"chan_id,omitempty"`
	ThingID string `json:"thing_id,omitempty"`
}

func (req connectThingReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	if req.ChanID == "" || req.ThingID == "" {
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

	if req.ChanID == "" || req.ThingID == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type disconnectChannelReq struct {
	token   string
	ThingID string `json:"thing_id,omitempty"`
	ChanID  string `json:"chan_id,omitempty"`
}

func (req disconnectChannelReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	if req.ChanID == "" || req.ThingID == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type assignReq struct {
	token   string
	groupID string
	Type    string `json:"type,omitempty"`
	Member  string `json:"member"`
}

func (req assignReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	if req.Type == "" || req.groupID == "" || req.Member == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type unassignReq struct {
	assignReq
}

func (req unassignReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}

	if req.groupID == "" || req.Member == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type publishReq struct {
	msg      messaging.Message
	thingKey string
	token    string
}

type tokenReq struct {
	username string
	password string
}

func (req publishReq) validate() error {
	if req.token == "" {
		return ui.ErrMalformedEntity
	}

	if req.thingKey == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type sendMessageReq struct {
	token string
}

func (req sendMessageReq) validate() error {
	if req.token == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type createUserReq struct {
	token    string
	Email    string                 `json:"email,omitempty"`
	Password string                 `json:"password,omitempty"`
	Groups   []string               `json:"group,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

func (req createUserReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.Email == "" || req.Password == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}

type createUsersReq struct {
	token     string
	Emails    []string                 `json:"emails,omitempty"`
	Passwords []string                 `json:"passwords,omitempty"`
	Groups    []string                 `json:"groups,omitempty"`
	Metadatas []map[string]interface{} `json:"metadatas,omitempty"`
}

func (req createUsersReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	for _, name := range req.Emails {
		if name == "" {
			return ui.ErrMalformedEntity
		}
	}
	for _, password := range req.Passwords {
		if password == "" {
			return ui.ErrMalformedEntity
		}
	}

	return nil
}

type listUsersReq struct {
	token string
}

func (req listUsersReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	return nil
}

type updateUserReq struct {
	token    string
	id       string
	Email    string                 `json:"email,omitempty"`
	Group    []string               `json:"group,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

func (req updateUserReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	return nil
}

type updateUserPasswordReq struct {
	token   string
	id      string
	OldPass string `json:"oldpass,omitempty"`
	NewPass string `json:"newpass,omitempty"`
}

func (req updateUserPasswordReq) validate() error {
	if req.token == "" {
		return ui.ErrUnauthorizedAccess
	}
	if req.OldPass == "" || req.NewPass == "" {
		return ui.ErrMalformedEntity
	}

	return nil
}
