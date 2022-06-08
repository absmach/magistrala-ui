// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"net/http"

	"github.com/mainflux/mainflux"
)

var (
	_ mainflux.Response = (*uiRes)(nil)
	_ mainflux.Response = (*tokenRes)(nil)
)

type uiRes struct {
	code    int
	headers map[string]string
	html    []byte
}

type tokenRes struct {
	token   string
	created bool
}

func (res tokenRes) Code() int {
	return http.StatusCreated
}

func (res tokenRes) Headers() map[string]string {
	if res.created {
		return map[string]string{
			"Set-Cookie": fmt.Sprintf("token%s;", res.token),
		}
	}

	return map[string]string{}
}

func (res tokenRes) Empty() bool {
	return res.token == ""
}

func (res uiRes) Code() int {
	if res.code == 0 {
		return http.StatusCreated
	}

	return res.code
}

func (res uiRes) Headers() map[string]string {
	if res.headers == nil {
		return map[string]string{}
	}

	return res.headers
}

func (res uiRes) Empty() bool {
	return res.html == nil
}
