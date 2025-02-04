package main

import (
	"time"

	"github.com/shopspring/decimal"
)

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

type Product struct {
	ID          int64           `json:"id"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Price       decimal.Decimal `json:"price"`
	Amount      int64           `json:"amount"`
	SellerID    int64           `json:"seller_id"`
	Version     int64           `json:"-"`
}
