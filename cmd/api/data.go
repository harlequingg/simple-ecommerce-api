package main

import "time"

type User struct {
	ID           int64     `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	Name         string    `json:"name"`
	Email        string    `json:"email"`
	PasswordHash []byte    `json:"-"`
	IsActivated  bool      `json:"is_activated"`
	Version      int64     `json:"-"`
}

type TokenScope string

const (
	ScopeAuthentication TokenScope = "authentication"
)

type Token struct {
	ID        int64      `json:"id"`
	Text      string     `json:"token"`
	Hash      []byte     `json:"-"`
	UserID    int64      `json:"-"`
	ExpiresAt time.Time  `json:"expiry"`
	Scope     TokenScope `json:"-"`
}
