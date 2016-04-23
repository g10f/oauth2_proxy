package providers

import (
	"github.com/g10f/oauth2_proxy/cookie"
)

type Provider interface {
	Data() *ProviderData
	GetEmailAddress(*SessionState) (string, error)
	Redeem(string, string) (*SessionState, error)
	ValidateRole(string) bool
	ValidateSessionState(*SessionState) bool
	GetLoginURL(redirectURI, finalRedirect string) string
	RefreshSessionIfNeeded(*SessionState) (bool, error)
	SessionFromCookie(string, *cookie.Cipher, string) (*SessionState, error)
	CookieForSession(*SessionState, *cookie.Cipher, string) (string, error)
}

func New(provider string, p *ProviderData) Provider {
	return NewDWBNProvider(p)
}
