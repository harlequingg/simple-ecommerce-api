package main

import (
	"time"

	"github.com/shopspring/decimal"
)

type User struct {
	ID           int64           `json:"id"`
	CreatedAt    time.Time       `json:"created_at"`
	Name         string          `json:"name"`
	Email        string          `json:"email"`
	PasswordHash []byte          `json:"-"`
	IsActivated  bool            `json:"is_activated"`
	Balance      decimal.Decimal `json:"balance"`
	Version      int32           `json:"-"`
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
	Quantity    int64           `json:"quantity"`
	Version     int32           `json:"-"`
}

type CartItem struct {
	ID        int64 `json:"id"`
	ProductID int64 `json:"product_id"`
	UserID    int64 `json:"-"`
	Quantity  int64 `json:"quantity"`
	Version   int32 `json:"-"`
}

type CartItemCheckout struct {
	ID       int64
	Quantity int64
	Version  int32
	Product  Product
}
