// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0
package google

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/absmach/magistrala-ui/ui/oauth2"
	golangoauth2 "golang.org/x/oauth2"
	googleoauth2 "golang.org/x/oauth2/google"
)

var scopes = []string{
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/userinfo.profile",
}

var _ oauth2.Handler = (*config)(nil)

type config struct {
	config *golangoauth2.Config
	state  string
}

// NewHandler returns a new Google OAuth2 handler.
func NewHandler(clientID, clientSecret, state, redirectURL string) oauth2.Handler {
	return &config{
		config: &golangoauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     googleoauth2.Endpoint,
			RedirectURL:  redirectURL,
			Scopes:       scopes,
		},
		state: state,
	}
}

func (conf *config) IsEnabled() bool {
	return conf.config.ClientID != "" && conf.config.ClientSecret != ""
}

func (conf *config) GenerateSignInURL() (string, error) {
	return conf.generateURL("signin")
}

func (conf *config) GenerateSignUpURL() (string, error) {
	return conf.generateURL("signup")
}

func (conf *config) generateURL(state string) (string, error) {
	URL, err := url.Parse(conf.config.Endpoint.AuthURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse google auth url: %s", err)
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
