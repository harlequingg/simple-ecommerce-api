package main

import (
	"context"
	"encoding/base32"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type userContextKey string

const (
	UserContextKey userContextKey = "USER_CONTEXT_KEY"
)

func getUserFromRequest(r *http.Request) *User {
	return r.Context().Value(UserContextKey).(*User)
}

func (app *Application) authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Authorization")
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeError(errors.New("invalid Authorization header"), http.StatusUnauthorized, w)
			return
		}
		parts := strings.Fields(authHeader)
		if len(parts) != 2 || parts[0] != "Bearer" {
			writeError(errors.New("invalid Authorization header"), http.StatusUnauthorized, w)
			return
		}
		token := parts[1]

		v := NewValidator()
		v.Check(token != "", "token", "must be provided")
		v.Check(len(token) == base32.StdEncoding.WithPadding(base32.NoPadding).EncodedLen(16), "token", "must be valid")

		if v.HasError() {
			writeError(errors.New("invalid token"), http.StatusUnauthorized, w)
			return
		}

		u, err := app.storage.GetUserFromToken(token, ScopeAuthentication)
		if err != nil {
			writeError(errors.New("invalid token"), http.StatusUnauthorized, w)
			return
		}

		ctx := context.WithValue(r.Context(), UserContextKey, u)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	}
}

func (app *Application) requirePermission(code string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := getUserFromRequest(r)
		if u == nil {
			writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
			return
		}
		permissions, err := app.storage.GetUserPermissions(u.ID)
		if err != nil {
			writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
			return
		}
		if !permissions.Has(code) {
			writeError(errors.New("you don't have permission to access this resource"), http.StatusForbidden, w)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func (app *Application) requireUserActivation(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := getUserFromRequest(r)
		if u == nil {
			writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
			return
		}
		if !u.IsActivated {
			writeError(errors.New("your user account must be activated to access this resource"), http.StatusForbidden, w)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func (app *Application) rateLimit(next http.Handler) http.HandlerFunc {
	type client struct {
		limiter  *rate.Limiter
		lastSeen time.Time
	}
	var (
		mu      sync.RWMutex
		clients = make(map[string]client)
	)
	go func() {
		for {
			time.Sleep(time.Minute)
			func() {
				mu.Lock()
				defer mu.Unlock()
				for ip, client := range clients {
					if time.Since(client.lastSeen) >= time.Minute*3 {
						delete(clients, ip)
					}
				}
			}()
		}
	}()
	return func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Println(err)
			writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
			return
		}
		mu.Lock()
		c, ok := clients[ip]
		if !ok {
			l := rate.NewLimiter(rate.Limit(app.config.limiter.maxRequestPerSecond), app.config.limiter.burst)
			c = client{
				limiter: l,
			}
		}
		c.lastSeen = time.Now()
		clients[ip] = c
		if !c.limiter.Allow() {
			mu.Unlock()
			writeError(errors.New("rate limit exceeded"), http.StatusTooManyRequests, w)
			return
		}
		mu.Unlock()
		next.ServeHTTP(w, r)
	}
}
