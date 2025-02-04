package main

import "net/http"

func ComposeRoutes(app *Application) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/healthcheck", app.healthCheckHandler)

	mux.HandleFunc("POST /v1/users", app.createUserHandler)
	mux.HandleFunc("GET /v1/users", app.authenticate(app.getUserHandler))
	mux.HandleFunc("PUT /v1/users", app.authenticate(app.updateUserHandler))
	mux.HandleFunc("DELETE /v1/users", app.authenticate(app.deleteUserHandler))

	mux.HandleFunc("POST /v1/tokens/authentication", app.createAuthenticationTokenHandler)

	mux.HandleFunc("POST /v1/products", app.authenticate(app.createProductHandler))
	mux.HandleFunc("GET /v1/products", app.getProductsHandler)
	mux.HandleFunc("GET /v1/products/{id}", app.getProductHandler)
	mux.HandleFunc("PUT /v1/products/{id}", app.authenticate(app.updateProductHandler))
	mux.HandleFunc("DELETE /v1/products/{id}", app.authenticate(app.deleteProductHandler))

	mux.HandleFunc("POST /v1/cart", app.authenticate(app.createCartItemHandler))
	mux.HandleFunc("GET /v1/cart", app.authenticate(app.getCartItems))
	mux.HandleFunc("GET /v1/cart/{id}", app.authenticate(app.getCartItem))
	mux.HandleFunc("PUT /v1/cart/{id}", app.authenticate(app.updateCartItem))
	mux.HandleFunc("DELETE /v1/cart", app.authenticate(app.deleteCartItems))
	mux.HandleFunc("DELETE /v1/cart/{id}", app.authenticate(app.deleteCartItem))

	return mux
}
