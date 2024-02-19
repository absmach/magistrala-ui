// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0
package ui

import (
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

const authEndpoint = "/oauth2/auth"

var scopes = []string{
	"email",
	"profile",
	"offline_access",
}

type KratosConfig struct {
	config *oauth2.Config
	state  string
}

func NewKratosConfig(baseURL, clientID, clientSecret, state, redirectURL string) KratosConfig {
	cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL: baseURL + authEndpoint,
		},
		RedirectURL: redirectURL,
		Scopes:      scopes,
	}

	return KratosConfig{
		config: cfg,
		state:  state,
	}
}

func (conf *KratosConfig) GenerateSignInURL() (string, error) {
	return conf.generateURL("signin")
}

func (conf *KratosConfig) GenerateSignUpURL() (string, error) {
	return conf.generateURL("signup")
}

func (conf *KratosConfig) generateURL(state string) (string, error) {
	URL, err := url.Parse(conf.config.Endpoint.AuthURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse kratos auth url: %s", err)
	}

	parameters := url.Values{}
	parameters.Add("client_id", conf.config.ClientID)
	parameters.Add("scope", strings.Join(conf.config.Scopes, " "))
	parameters.Add("redirect_uri", conf.config.RedirectURL)
	parameters.Add("response_type", "code")
	// login or register state is prepended to the state to be used in the callback
	parameters.Add("state", fmt.Sprintf("%s-%s", state, conf.state))
	URL.RawQuery = parameters.Encode()

	return URL.String(), nil
}
