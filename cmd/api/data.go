package main

import (
	"slices"
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
	ScopeActivation     TokenScope = "activation"
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

type OrderStatusID int64

const (
	OrderStatusInProgress OrderStatusID = 1
	OrderStatusDelivered  OrderStatusID = 2
	OrderStatusCancelled  OrderStatusID = 3
)

type OrderStatus struct {
	ID     int64  `json:"id"`
	Status string `json:"status"`
}

type Order struct {
	ID          int64     `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UserID      int64     `json:"user_id"`
	StatusID    int64     `json:"status_id"`
	CompletedAt time.Time `json:"completed_at"`
	Version     int32     `json:"-"`
}

type OrderItem struct {
	ID        int64           `json:"id"`
	OrderID   int64           `json:"order_id"`
	ProductID int64           `json:"product_id"`
	Quantity  int64           `json:"quantity"`
	Price     decimal.Decimal `json:"price"`
}

type OrderItems struct {
	Order Order       `json:"order"`
	Items []OrderItem `json:"items"`
}

type Transation struct {
	ID        int64           `json:"id"`
	UserID    int64           `json:"user_id"`
	Signature string          `json:"signature"`
	Amount    decimal.Decimal `json:"amount"`
}

type Permissions []string

func (p Permissions) Has(code string) bool {
	return slices.Index(p, code) != -1
}
