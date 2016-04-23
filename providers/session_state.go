package providers

import (
	"fmt"
	"time"
	//"log"

	"github.com/g10f/oauth2_proxy/cookie"
	"github.com/dgrijalva/jwt-go"
)

type SessionState struct {
	Issuer       string
	AccessToken  string
	ExpiresOn    time.Time
	IssuedAt     time.Time
	RefreshToken string
	Email        string
	User         string
	Subject      string
	Roles        string
	UserName     string
}

func (s *SessionState) IsExpired() bool {
	if !s.ExpiresOn.IsZero() && s.ExpiresOn.Before(time.Now()) {
		return true
	}
	return false
}

func (s *SessionState) EncodeSessionState(c *cookie.Cipher, secret string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["sub"] = s.User
	token.Claims["email"] = s.Email
	token.Claims["name"] = s.UserName
	token.Claims["roles"] = s.Roles
	token.Claims["exp"] = s.ExpiresOn.Unix()

	if c == nil || s.AccessToken == "" {
		return token.SignedString([]byte(secret))
	}
	var err error
	a := s.AccessToken
	if a != "" {
		a, err = c.Encrypt(a)
		if err != nil {
			return "", err
		}
		token.Claims["a"] = a

	}
	r := s.RefreshToken
	if r != "" {
		r, err = c.Encrypt(r)
		if err != nil {
			return "", err
		}
		token.Claims["r"] = r
	}
	return token.SignedString([]byte(secret))
}

func (s *SessionState) userOrEmail() string {
	u := s.User
	if s.Email != "" {
		u = s.Email
	}
	return u
}

func DecodeSessionState(v string, c *cookie.Cipher, secret string) (s *SessionState, err error) {
	token, err := jwt.Parse(v, func(token *jwt.Token) (interface{}, error) {
		if token.Header["alg"].(string) != "HS256" {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	claims := token.Claims
	user, ok := claims["sub"].(string)
	if !ok {
		err = fmt.Errorf("No sub in claims %v", claims)
		return
	}
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	roles, _ := claims["roles"].(string)
	a, ok := claims["a"].(string)
	if ok {
		a, err = c.Decrypt(a)
		if err != nil {
			return nil, err
		}
	}
	r, ok := claims["r"].(string)
	if ok {
		r, err = c.Decrypt(r)
		if err != nil {
			return nil, err
		}
	}
	exp, _ := claims["exp"].(float64)
	expiresOn := time.Unix(int64(exp), 0)
	s = &SessionState{User: user, UserName: name, Email: email, AccessToken: a, ExpiresOn: expiresOn, RefreshToken: r, Roles: roles}
	return s, nil
}
