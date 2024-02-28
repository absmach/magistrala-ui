// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0
package google

import (
	"fmt"
	"net/url"
	"strings"

	mgoauth2 "github.com/absmach/magistrala-ui/ui/oauth2"
	"golang.org/x/oauth2"
	googleoauth2 "golang.org/x/oauth2/google"
)

var scopes = []string{
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/userinfo.profile",
}

var _ mgoauth2.Handler = (*config)(nil)

type config struct {
	oauth2 *oauth2.Config
	state  string
}

// NewHandler returns a new Google OAuth2 handler.
func NewHandler(cfg mgoauth2.Config) mgoauth2.Handler {
	return &config{
		oauth2: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     googleoauth2.Endpoint,
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
		},
		state: cfg.State,
	}
}

func (cfg *config) IsEnabled() bool {
	return cfg.oauth2.ClientID != "" && cfg.oauth2.ClientSecret != ""
}

func (cfg *config) GenerateSignInURL() (string, error) {
	return cfg.generateURL("signin")
}

func (cfg *config) GenerateSignUpURL() (string, error) {
	return cfg.generateURL("signup")
}

func (cfg *config) generateURL(state string) (string, error) {
	URL, err := url.Parse(cfg.oauth2.Endpoint.AuthURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse google auth url: %s", err)
	}

	parameters := url.Values{}
	parameters.Add("client_id", cfg.oauth2.ClientID)
	parameters.Add("scope", strings.Join(cfg.oauth2.Scopes, " "))
	parameters.Add("redirect_uri", cfg.oauth2.RedirectURL)
	parameters.Add("response_type", "code")
	parameters.Add("access_type", "offline")
	// prompt=consent is required to get the refresh token
	parameters.Add("prompt", "consent")
	// login or register state is prepended to the state to be used in the callback
	parameters.Add("state", fmt.Sprintf("%s-%s", state, cfg.state))
	URL.RawQuery = parameters.Encode()

	return URL.String(), nil
}
