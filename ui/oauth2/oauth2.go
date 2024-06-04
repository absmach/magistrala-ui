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

// Provider is an interface that provides the OAuth2 flow for a specific provider
// (e.g. Google, GitHub, etc.)
//
//go:generate mockery --name Provider --output=./mocks --filename provider.go --quiet --note "Copyright (c) Abstract Machines"
type Provider interface {
	// Name returns the name of the provider.
	// This should be unique across all providers and in lowercase.
	Name() string

	// Icon returns the icon of the provider.
	Icon() string

	// IsEnabled returns whether the provider is enabled.
	IsEnabled() bool

	// GenerateURL generates a URL for the sign-in flow and sign-up flow.
	GenerateURL() (string, error)
}
