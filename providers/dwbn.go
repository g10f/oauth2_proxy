package providers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type DWBNProvider struct {
	*ProviderData
}

type DWBNIdToken struct {
	Iss        string `json:"iss"`
	Sub        string `json:"sub"`
	Aud        string `json:"aud"`
	Exp        int    `json:"exp"`
	Iat        int    `json:"iat"`
	AuthTime   int    `json:"auth_time"`
	Acr        string `json:"acr"`
	Email      string `json:"email"`
	Name       string `json:"name"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
	Roles      string `json:"roles"`
}

func NewDWBNProvider(p *ProviderData) *DWBNProvider {
	p.ProviderName = "DWBN"
	if p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "sso.dwbn.org",
			Path:   "/oauth2/authorize/",
		}
	}
	if p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "sso.dwbn.org",
			Path:   "/oauth2/token/"}
	}
	if p.ValidateURL.String() == "" {
		p.ValidateURL = &url.URL{
			Scheme: "https",
			Host:   "sso.dwbn.org",
			Path:   "/oauth2/tokeninfo/"}
	}
	if p.Scope == "" {
		p.Scope = "openid profile email"
	}

	return &DWBNProvider{
		ProviderData: p,
	}
}

func dwbnIdTokenFromIdToken(idToken string) (*DWBNIdToken, error) {
	// id_token is a base64 encode ID token payload
	// https://developers.google.com/accounts/docs/OAuth2Login#obtainuserinfo
	jwt := strings.Split(idToken, ".")
	b, err := jwtDecodeSegment(jwt[1])
	if err != nil {
		return nil, err
	}
	dwbnIdToken := DWBNIdToken{}
	err = json.Unmarshal(b, &dwbnIdToken)
	log.Printf("dwbnIdToken: %v", dwbnIdToken)
	if err != nil {
		return nil, err
	}
	if dwbnIdToken.Email == "" {
		return nil, errors.New("missing email")
	}
	return &dwbnIdToken, nil
}

func (p *DWBNProvider) Redeem(redirectURL, code string) (s *SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return
	}

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		IdToken      string `json:"id_token"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err != nil {
		return
	}
	dwbnIdToken, err := dwbnIdTokenFromIdToken(jsonResponse.IdToken)
	if err != nil {
		return
	}
	s = &SessionState{
		AccessToken:  jsonResponse.AccessToken,
		ExpiresOn:    time.Now().Add(time.Duration(jsonResponse.ExpiresIn) * time.Second).Truncate(time.Second),
		RefreshToken: jsonResponse.RefreshToken,
		Email:        dwbnIdToken.Email,
		User:         dwbnIdToken.Sub,
	}
	return
}
