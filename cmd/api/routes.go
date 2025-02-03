package main

import "net/http"

func ComposeRoutes(app *Application) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/healthcheck", app.healthCheckHandler)

	mux.HandleFunc("POST /v1/users", app.createUserHandler)
	mux.HandleFunc("GET /v1/users/{id}", app.getUserHandler)
	mux.HandleFunc("PUT /v1/users/{id}", app.updateUserHandler)
	mux.HandleFunc("DELETE /v1/users/{id}", app.deleteUserHandler)

	return mux
}
