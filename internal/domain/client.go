package domain

import "time"

type Client struct {
	ID          string
	Secret      string
	Name        string
	RedirectURI string
}

type AuthorizationCode struct {
	Code        string
	UserID      string
	ClientID    string
	RedirectURI string
	ExpiresAt   time.Time
}

func (ac *AuthorizationCode) IsExpired() bool {
	return time.Now().After(ac.ExpiresAt)
}

type Session struct {
	ID        string
	UserID    string
	ExpiresAt time.Time
}

func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}
