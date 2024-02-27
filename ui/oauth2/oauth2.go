// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0
package oauth2

// Config is the configuration for the OAuth2 provider.
type Config struct {
	ClientID     string `env:"CLIENT_ID"       envDefault:""`
	ClientSecret string `env:"CLIENT_SECRET"   envDefault:""`
	State        string `env:"STATE"           envDefault:""`
	RedirectURL  string `env:"REDIRECT_URL"    envDefault:""`
}

// Handler is an interface that provides the OAuth2 flow for a specific provider
// (e.g. Google, GitHub, etc.)
type Handler interface {
	// IsEnabled returns whether the provider is enabled.
	IsEnabled() bool
	// GenerateSignInURL generates a URL for the sign-in flow.
	GenerateSignInURL() (string, error)
	// GenerateSignUpURL generates a URL for the sign-up flow.
	GenerateSignUpURL() (string, error)
}

// State is the state of the OAuth2 flow.
type State uint8

// Provider is the provider of the OAuth2 flow.
type Provider uint8

const (
	// SignIn is the state for the sign-in flow.
	SignIn State = iota
	// SignUp is the state for the sign-up flow.
	SignUp
)

// Google is the provider for Google.
const Google Provider = iota

func (s State) String() string {
	switch s {
	case SignIn:
		return "signin"
	case SignUp:
		return "signup"
	default:
		return "unknown"
	}
}

func (p Provider) String() string {
	switch p {
	case Google:
		return "google"
	default:
		return "unknown"
	}
}
