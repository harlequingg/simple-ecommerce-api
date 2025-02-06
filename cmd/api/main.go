package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/stripe/stripe-go/v81"
)

type Config struct {
	port        int
	environment string
	db          struct {
		dsn string
	}
}

type Application struct {
	config  Config
	storage *Storage
}

const (
	version = "1.0.0"
)

func main() {
	log.SetFlags(log.LUTC | log.Llongfile)

	stripe.Key = os.Getenv("STRIPE_SECRET_KEY")
	var cfg Config

	defaultPort, err := strconv.Atoi(os.Getenv("PORT"))
	if err != nil {
		defaultPort = 8080
	}

	defaultEnv := os.Getenv("ENV")
	if defaultEnv == "" {
		defaultEnv = "development"
	}

	flag.IntVar(&cfg.port, "port", defaultPort, "Listen port of the Server")
	flag.StringVar(&cfg.environment, "env", defaultEnv, `Environment ("development" or "production")`)
	flag.StringVar(&cfg.db.dsn, "db-dsn", os.Getenv("DB_DSN"), "Database DSN")
	flag.Parse()

	storage, err := NewStorage(cfg.db.dsn)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Connected to database")

	app := &Application{
		config:  cfg,
		storage: storage,
	}

	srv := http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.port),
		Handler:      ComposeRoutes(app),
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	quit := make(chan error)
	done := make(chan struct{})

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		close(done)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		err := srv.Shutdown(ctx)
		quit <- err
	}()

	go func() {
		ticker := time.NewTicker(time.Minute)
		for {
			select {
			case <-done:
				log.Println("Tokens background goroutine was shutdown gracefully")
				return
			case <-ticker.C:
				err := app.storage.DeleteExpiredTokens()
				if err != nil {
					log.Println("Tokens background goroutine: ", err)
				}
			}
		}
	}()

	log.Printf("Starting server on port: %d\n", cfg.port)

	err = srv.ListenAndServe()
	if err != nil {
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}

	err = <-quit
	if err != nil {
		log.Fatal(err)
	}

	close(quit)
	log.Println("Server was shutdown gracefully")
}
