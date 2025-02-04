package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"errors"
	"time"

	_ "github.com/lib/pq"
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
	query := `SELECT created_at, name, email, password_hash, is_activated, version
			  FROM users
			  WHERE id = $1`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	u := User{}
	u.ID = id

	args := []any{u.ID}
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&u.CreatedAt, &u.Name, &u.Email, &u.PasswordHash, &u.IsActivated, &u.Version)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &u, nil
}

func (s *Storage) GetUserByEmail(email string) (*User, error) {
	query := `SELECT id, created_at, name, password_hash, is_activated, version
			  FROM users
			  WHERE email = $1`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	u := User{}
	u.Email = email

	args := []any{u.Email}
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&u.ID, &u.CreatedAt, &u.Name, &u.PasswordHash, &u.IsActivated, &u.Version)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return &u, nil
}

func (s *Storage) UpdateUser(u *User) error {
	query := `UPDATE users
			  SET name = $1, email = $2, password_hash = $3, is_activated = $4, version = version + 1  
			  WHERE id = $5 AND version = $6 
			  RETURNING version`

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	args := []any{u.Name, u.Email, u.PasswordHash, u.IsActivated, u.ID, u.Version}
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
	query := `SELECT u.id, u.created_at, u.name, u.email, u.password_hash, u.is_activated, u.version
			  FROM users as u
			  INNER JOIN tokens as t
			  on u.id = t.user_id
			  WHERE t.hash = $1 AND t.scope = $2 AND t.expires_at > NOW()`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var u User

	args := []any{hash[:], scope}
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&u.ID, &u.CreatedAt, &u.Name, &u.Email, &u.PasswordHash, &u.IsActivated, &u.Version)
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
