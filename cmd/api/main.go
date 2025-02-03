package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

type Config struct {
	port int
}

type Application struct {
	config Config
}

const (
	version     = "1.0.0"
	environment = "development"
)

func (app *Application) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	res := struct {
		Version     string `json:"version"`
		Environment string `json:"env"`
	}{Version: version, Environment: environment}
	data, err := json.Marshal(res)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func main() {
	var cfg Config
	p, _ := strconv.Atoi(os.Getenv("PORT"))
	flag.IntVar(&cfg.port, "port", p, "Listen port of the Server")

	app := &Application{
		config: cfg,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/healthcheck", app.healthCheckHandler)

	srv := http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.port),
		Handler:      mux,
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	err := srv.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
