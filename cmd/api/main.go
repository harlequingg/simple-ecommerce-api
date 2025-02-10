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
	smtp struct {
		host     string
		port     int
		username string
		password string
		sender   string
	}
	limiter struct {
		maxRequestPerSecond float64
		burst               int
		enabled             bool
	}
}

type Application struct {
	config  Config
	storage *Storage
	mailer  *Mailer
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
	smtpPort, err := strconv.Atoi(os.Getenv("SMTP_PORT"))
	if err != nil {
		log.Fatal(err)
	}

	flag.IntVar(&cfg.smtp.port, "smtp-port", smtpPort, "SMTP port")
	flag.StringVar(&cfg.smtp.username, "smtp-username", os.Getenv("SMTP_USERNAME"), "SMTP host")
	flag.StringVar(&cfg.smtp.password, "smtp-password", os.Getenv("SMTP_PASSWORD"), "SMTP password")
	flag.StringVar(&cfg.smtp.sender, "smtp-sender", os.Getenv("SMTP_SENDER"), "SMTP sender")

	flag.Float64Var(&cfg.limiter.maxRequestPerSecond, "limiter-max-rps", 2, "Rate Limiter max requests per second")
	flag.IntVar(&cfg.limiter.burst, "limiter-burst", 4, "Rate Limiter max burst")
	flag.BoolVar(&cfg.limiter.enabled, "limiter-enabled", true, "Enable rate limiter")

	flag.Parse()

	storage, err := NewStorage(cfg.db.dsn)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Connected to database")

	app := &Application{
		config:  cfg,
		storage: storage,
		mailer:  NewMailer(cfg.smtp.host, cfg.smtp.port, cfg.smtp.username, cfg.smtp.password, cfg.smtp.sender),
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
				n, err := app.storage.DeleteExpiredTokens()
				if err != nil {
					log.Println("Tokens goroutine: ", err)
				} else {
					log.Printf("Tokens goroutine: deleted %d tokens", n)
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
