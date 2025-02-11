package main

import "net/http"

func ComposeRoutes(app *Application) http.Handler {
	mux := http.NewServeMux()

	fs := http.FileServer(http.Dir("./public"))
	mux.Handle("GET /static/", http.StripPrefix("/static/", fs))

	mux.HandleFunc("GET /v1/healthcheck", app.healthCheckHandler)

	mux.HandleFunc("POST /v1/users", app.createUserHandler)
	mux.HandleFunc("GET /v1/users/{id}", app.authenticate(app.getUserHandler))
	mux.HandleFunc("PUT /v1/users/{id}", app.authenticate(app.updateUserHandler))
	mux.HandleFunc("DELETE /v1/users/{id}", app.authenticate(app.deleteUserHandler))

	mux.HandleFunc("POST /v1/tokens/authentication", app.createAuthenticationTokenHandler)
	mux.HandleFunc("POST /v1/tokens/activation", app.createUserActivationTokenHandler)
	mux.HandleFunc("PUT /v1/tokens/activation", app.activateUserHandler)

	mux.HandleFunc("POST /v1/products", app.authenticate(app.requirePermission("products:create", app.createProductHandler)))
	mux.HandleFunc("GET /v1/products", app.authenticate(app.requirePermission("products:read", app.getProductsHandler)))
	mux.HandleFunc("GET /v1/products/{id}", app.authenticate(app.requirePermission("products:read", app.getProductHandler)))
	mux.HandleFunc("PUT /v1/products/{id}", app.authenticate(app.requirePermission("products:update", app.updateProductHandler)))
	mux.HandleFunc("DELETE /v1/products/{id}", app.authenticate(app.requirePermission("products:delete", app.deleteProductHandler)))

	mux.HandleFunc("POST /v1/cart-items", app.authenticate(app.createCartItemHandler))
	mux.HandleFunc("GET /v1/cart-items", app.authenticate(app.getCartItems))
	mux.HandleFunc("GET /v1/cart-items/{id}", app.authenticate(app.getCartItem))
	mux.HandleFunc("PUT /v1/cart-items/{id}", app.authenticate(app.updateCartItem))
	mux.HandleFunc("DELETE /v1/cart-items", app.authenticate(app.deleteCartItems))
	mux.HandleFunc("DELETE /v1/cart-items/{id}", app.authenticate(app.deleteCartItem))
	mux.HandleFunc("POST /v1/cart-items/checkout", app.authenticate(app.checkoutHandler))

	mux.HandleFunc("POST /v1/balances", app.authenticate(app.addToBalanceHandler))
	mux.HandleFunc("POST /v1/balances-webhook", app.balancesWebhookHandler)

	mux.HandleFunc("GET /v1/orders/{id}", app.authenticate(app.getOrderHandler))
	mux.HandleFunc("GET /v1/orders", app.authenticate(app.getOrdersHandler))
	mux.HandleFunc("PUT /v1/orders/{id}", app.authenticate(app.updateOrderHandler))

	if app.config.limiter.enabled {
		return app.enableCORS(app.recoverFromPanic(app.rateLimit(mux)))
	}

	return app.enableCORS(app.recoverFromPanic(mux))
}
