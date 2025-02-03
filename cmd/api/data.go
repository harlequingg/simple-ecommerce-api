package main

import "time"

type User struct {
	ID          int64     `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	Name        string    `json:"name"`
	Email       string    `json:"email"`
	Password    []byte    `json:"-"`
	IsActivated bool      `json:"is_activated"`
	Version     int64     `json:"-"`
}
