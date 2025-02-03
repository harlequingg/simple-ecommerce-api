package main

import "net/http"

func ComposeRoutes(app *Application) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/healthcheck", app.healthCheckHandler)
	return mux
}
