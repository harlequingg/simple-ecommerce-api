package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/shopspring/decimal"
)

type Storage struct {
	db *sql.DB
}

func NewStorage(connStr string) (*Storage, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}

	// TODO: make this configurable
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(25)
	db.SetConnMaxIdleTime(15 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = db.PingContext(ctx)
	if err != nil {
		return nil, err
	}
	return &Storage{db: db}, nil
}

func (s *Storage) CreateUser(name, email string, passwordHash []byte) (*User, error) {
	query := `INSERT INTO users(name, email, password_hash, is_activated)
	          VALUES ($1, $2, $3, $4)
			  RETURNING id, created_at, version`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	u := User{}
	u.Name = name
	u.Email = email
	u.PasswordHash = passwordHash
	u.IsActivated = false

	args := []any{u.Name, u.Email, u.PasswordHash, u.IsActivated}
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&u.ID, &u.CreatedAt, &u.Version)
	if err != nil {
		return nil, err
	}

	return &u, nil
}

func (s *Storage) GetUserById(id int64) (*User, error) {
	query := `SELECT created_at, name, email, password_hash, is_activated, balance, version
			  FROM users
			  WHERE id = $1`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	u := User{}
	u.ID = id

	args := []any{u.ID}
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&u.CreatedAt, &u.Name, &u.Email, &u.PasswordHash, &u.IsActivated, &u.Balance, &u.Version)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &u, nil
}

func (s *Storage) GetUserByEmail(email string) (*User, error) {
	query := `SELECT id, created_at, name, password_hash, is_activated, balance, version
			  FROM users
			  WHERE email = $1`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	u := User{}
	u.Email = email

	args := []any{u.Email}
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&u.ID, &u.CreatedAt, &u.Name, &u.PasswordHash, &u.IsActivated, &u.Balance, &u.Version)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &u, nil
}

func (s *Storage) UpdateUser(u *User) error {
	log.Println(u.Balance)
	query := `UPDATE users
			  SET name = $1, email = $2, password_hash = $3, is_activated = $4, balance = $5, version = version + 1  
			  WHERE id = $6 AND version = $7 
			  RETURNING version`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	args := []any{u.Name, u.Email, u.PasswordHash, u.IsActivated, u.Balance, u.ID, u.Version}
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&u.Version)
	if err != nil {
		return err
	}
	return nil
}

func (s *Storage) DeleteUser(u *User) error {
	query := `DELETE FROM users
			  WHERE id = $1`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	args := []any{u.ID}
	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}

func (s *Storage) CreateToken(userID int64, duration time.Duration, scope TokenScope) (*Token, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	text := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	hash := sha256.Sum256([]byte(text))
	expires_at := time.Now().Add(duration)
	query := `INSERT INTO tokens(hash, user_id, expires_at, scope)
			  VALUES ($1, $2, $3, $4)
			  RETURNING id`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t := &Token{
		Text:      text,
		Hash:      hash[:],
		ExpiresAt: expires_at,
		UserID:    userID,
		Scope:     scope,
	}

	args := []any{hash[:], userID, expires_at, scope}
	err = s.db.QueryRowContext(ctx, query, args...).Scan(&t.ID)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (s *Storage) GetUserFromToken(text string, scope TokenScope) (*User, error) {
	hash := sha256.Sum256([]byte(text))
	query := `SELECT u.id, u.created_at, u.name, u.email, u.password_hash, u.is_activated, u.balance, u.version
			  FROM users as u
			  INNER JOIN tokens as t
			  on u.id = t.user_id
			  WHERE t.hash = $1 AND t.scope = $2 AND t.expires_at > NOW()`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var u User

	args := []any{hash[:], scope}
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&u.ID, &u.CreatedAt, &u.Name, &u.Email, &u.PasswordHash, &u.IsActivated, &u.Balance, &u.Version)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Storage) DeleteTokensForUser(userID int64, scope TokenScope) error {
	query := `DELETE FROM tokens
			  WHERE user_id = $1 AND scope = $2`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	args := []any{userID, scope}
	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}

func (s *Storage) DeleteExpiredTokens() error {
	query := `DELETE FROM tokens
			  WHERE NOW() > expires_at`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.db.ExecContext(ctx, query)
	return err
}

func (s *Storage) CreateProduct(name, description string, price decimal.Decimal, quantity int64) (*Product, error) {
	query := `INSERT INTO products(name, description, price, quantity)
			  VALUES ($1, $2, $3, $4)
			  RETURNING id, created_at, updated_at, version`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	p := Product{
		Name:        name,
		Description: description,
		Price:       price,
		Quantity:    quantity,
	}

	args := []any{name, description, price, quantity}
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt, &p.Version)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Storage) GetProductByID(id int64) (*Product, error) {
	query := `SELECT created_at, updated_at, name, description, price, quantity, version
			  FROM products
			  WHERE id = $1`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	args := []any{id}
	p := Product{
		ID: id,
	}
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&p.CreatedAt, &p.UpdatedAt, &p.Name, &p.Description, &p.Price, &p.Quantity, &p.Version)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &p, nil
}

func (s *Storage) GetProducts(name, description, sort string, minPrice, maxPrice decimal.Decimal, page, pageSize int) ([]Product, int, error) {
	op := "ASC"
	column := sort
	if strings.HasPrefix(sort, "-") {
		column = strings.TrimPrefix(sort, "-")
		op = "DESC"
	}
	sortStr := fmt.Sprintf("%s %s", column, op)
	if column != "id" {
		sortStr = fmt.Sprintf("%s %s, id ASC", column, op)
	}
	query := fmt.Sprintf(`SELECT COUNT(*) OVER(), id, created_at, updated_at, name, description, price, quantity, version
			  FROM products
			  WHERE ($1 = '' OR to_tsvector('simple', name) @@ plainto_tsquery('simple', $1))
			  AND ($2 = '' OR to_tsvector('simple', description) @@ plainto_tsquery('simple', $2))
			  AND (price BETWEEN $3 AND $4)
			  ORDER BY %s
			  LIMIT $5 OFFSET $6`, sortStr)
	limit := pageSize
	offset := (page - 1) * pageSize
	args := []any{name, description, minPrice, maxPrice, limit, offset}
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	total := 0
	products := []Product{}
	for rows.Next() {
		p := Product{}
		err := rows.Scan(&total, &p.ID, &p.CreatedAt, &p.UpdatedAt, &p.Name, &p.Description, &p.Price, &p.Quantity, &p.Version)
		if err != nil {
			return nil, 0, err
		}
		products = append(products, p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return products, total, nil
}

func (s *Storage) UpdateProduct(p *Product) error {
	query := `UPDATE products
	          SET name = $1, description = $2, price = $3, quantity = $4, updated_at = NOW(), version = version + 1
			  WHERE id = $5 AND version = $6
			  RETURNING version`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	args := []any{p.Name, p.Description, p.Price, p.Quantity, p.ID, p.Version}
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&p.Version)
	if err != nil {
		return err
	}
	return nil
}

func (s *Storage) DeleteProduct(p *Product) error {
	query := `DELETE FROM products
			  WHERE id = $1`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	args := []any{p.ID}
	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}

func (s *Storage) CreateCartItem(productID int64, userID int64, quantity int64) (*CartItem, error) {
	query := `INSERT INTO cart_items(product_id, user_id, quantity)
			  VALUES ($1, $2, $3)
			  RETURNING id`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	args := []any{productID, userID, quantity}
	c := CartItem{
		ProductID: productID,
		UserID:    userID,
		Quantity:  quantity,
	}
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&c.ID)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Storage) GetCartItemById(cartItemID int64) (*CartItem, error) {
	query := `SELECT product_id, user_id, quantity, version
			  FROM cart_items
			  WHERE id = $1`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	args := []any{cartItemID}
	item := CartItem{
		ID: cartItemID,
	}
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&item.ProductID, &item.UserID, &item.Quantity, &item.Version)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &item, err
}

func (s *Storage) GetCartItems(userID int64) ([]CartItem, error) {
	query := `SELECT id, product_id, quantity, version
			  FROM cart_items
			  WHERE user_id = $1
			  ORDER BY id ASC`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	args := []any{userID}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	cartItems := []CartItem{}
	for rows.Next() {
		item := CartItem{
			UserID: userID,
		}
		err := rows.Scan(&item.ID, &item.ProductID, &item.Quantity, &item.Version)
		if err != nil {
			return nil, err
		}
		cartItems = append(cartItems, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return cartItems, nil
}

func (s *Storage) UpdateCartItem(cartItem *CartItem) error {
	query := `UPDATE cart_items
			  SET quantity = $1, version = version + 1
			  WHERE id = $2 AND version = $3
			  RETURNING version`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	args := []any{cartItem.Quantity, cartItem.ID, cartItem.Version}
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&cartItem.Version)
	if err != nil {
		return err
	}
	return nil
}

func (s *Storage) DeleteCartItem(cartItem *CartItem) error {
	query := `DELETE FROM cart_items
			  WHERE id = $1`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	args := []any{cartItem.ID}
	_, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	return nil
}

func (s *Storage) DeleteCartItems(userID int64) error {
	query := `DELETE FROM cart_items
			  WHERE user_id = $1`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	args := []any{userID}
	_, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}
	return nil
}

func (s *Storage) CheckoutCart(u *User) (decimal.Decimal, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ops := &sql.TxOptions{
		Isolation: sql.LevelSerializable,
	}
	tx, err := s.db.BeginTx(ctx, ops)
	if err != nil {
		log.Println(err)
		return decimal.Zero, err
	}
	query0 := `SELECT c.id, c.quantity, c.version, p.id, p.name, p.price, p.quantity, p.version 
			   FROM cart_items as c
			   INNER JOIN products as p
			   ON c.product_id = p.id
			   WHERE c.user_id = $1`

	rows, err := tx.QueryContext(ctx, query0, u.ID)
	if err != nil {
		log.Println(err)
		tx.Rollback()
		return decimal.Zero, err
	}
	defer rows.Close()

	type cartItemCheckout struct {
		ID       int64
		Quantity int64
		Version  int32
		Product  Product
	}

	items := []cartItemCheckout{}
	total := decimal.Zero
	for rows.Next() {
		item := cartItemCheckout{}
		p := &item.Product
		err := rows.Scan(&item.ID, &item.Quantity, &item.Version, &p.ID, &p.Name, &p.Price, &p.Quantity, &p.Version)
		if err != nil {
			log.Println(err)
			tx.Rollback()
			return decimal.Zero, err
		}
		if item.Quantity > p.Quantity {
			tx.Rollback()
			return decimal.Zero, errors.New("product %d-%v has only %d in stock and you want %d")
		}
		items = append(items, item)
		total = total.Add(item.Product.Price.Mul(decimal.NewFromInt(item.Quantity)))
	}
	if err = rows.Err(); err != nil {
		tx.Rollback()
		return decimal.Zero, err
	}

	if len(items) == 0 {
		tx.Rollback()
		return decimal.Zero, errors.New("cart is empty")
	}

	if total.GreaterThan(u.Balance) {
		tx.Rollback()
		return decimal.Zero, fmt.Errorf("your total is %v but you only have %v", total, u.Balance)
	}

	query1 := `UPDATE products
			   SET quantity = quantity - $1, version = version + 1
			   WHERE id = $2 AND version = $3`

	for _, item := range items {
		_, err = tx.ExecContext(ctx, query1, item.Quantity, item.Product.ID, item.Product.Version)
		if err != nil {
			log.Println(err)
			tx.Rollback()
			return decimal.Zero, err
		}
	}

	query2 := `UPDATE users
			   SET balance = balance - $1, version = version + 1
	           WHERE id = $2 AND version = $3`

	_, err = tx.ExecContext(ctx, query2, total, u.ID, u.Version)
	if err != nil {
		log.Println(err)
		tx.Rollback()
		return decimal.Zero, err
	}

	query4 := `INSERT INTO orders(user_id)
	           VALUES ($1)
			   RETURNING id`

	orderID := int64(0)
	err = tx.QueryRowContext(ctx, query4, u.ID).Scan(&orderID)
	if err != nil {
		log.Println(err)
		tx.Rollback()
		return decimal.Zero, err
	}

	query5 := `INSERT INTO order_items(order_id, product_id, quantity, price)
			   VALUES ($1, $2, $3, $4)`

	for _, item := range items {
		_, err = tx.ExecContext(ctx, query5, orderID, item.Product.ID, item.Quantity, item.Product.Price)
		if err != nil {
			log.Println(err)
			tx.Rollback()
			return decimal.Zero, err
		}
	}

	query3 := `DELETE FROM cart_items
			   WHERE user_id = $1`

	_, err = tx.ExecContext(ctx, query3, u.ID)
	if err != nil {
		log.Println(err)
		tx.Rollback()
		return decimal.Zero, err
	}

	err = tx.Commit()
	if err != nil {
		log.Println(err)
		return decimal.Zero, err
	}

	return total, nil
}
