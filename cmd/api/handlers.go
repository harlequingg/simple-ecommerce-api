package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/shopspring/decimal"
	"github.com/stripe/stripe-go/v81"
	"github.com/stripe/stripe-go/v81/checkout/session"
	"github.com/stripe/stripe-go/webhook"
	"golang.org/x/crypto/bcrypt"
)

//go:embed templates
var templates embed.FS

func (app *Application) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	res := map[string]any{
		"version":     version,
		"environment": app.config.environment,
	}
	writeJSON(res, http.StatusOK, w)
}

func (app *Application) createUserHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(err, http.StatusBadRequest, w)
		return
	}

	v := NewValidator()
	v.CheckUsername(req.Name)
	v.CheckEmail(req.Email)
	v.CheckPassword(req.Password)

	if v.HasError() {
		writeValidatorErrors(v, w)
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeServerError(w)
		return
	}

	permissions := []string{"products:read"}
	u, err := app.storage.CreateUser(req.Name, req.Email, passwordHash, permissions)
	if err != nil {
		writeServerError(w)
		return
	}

	token, err := app.storage.CreateToken(u.ID, 5*time.Minute, ScopeActivation)
	if err != nil {
		writeServerError(w)
		return
	}

	app.background(func() {
		tmpl, err := template.ParseFS(templates, "templates/*.gotmpl")
		if err != nil {
			log.Println(err)
			return
		}
		err = app.mailer.Send(req.Email, tmpl, map[string]any{"token": token.Text})
		if err != nil {
			log.Printf("failed to send email to %s: %v\n", req.Email, err)
		}
	})

	res := map[string]any{
		"message": fmt.Sprintf("an activation token was sent to email %s", req.Email),
		"user":    u,
	}
	writeJSON(res, http.StatusCreated, w)
}

func (app *Application) getUserHandler(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromPathValue(r)
	if err != nil {
		writeBadRequest(err, w)
		return
	}
	u := getUserFromRequest(r)
	if u.ID != int64(id) {
		writeForbidden(w)
		return
	}
	res := map[string]any{
		"user": u,
	}
	writeOK(res, w)
}

func (app *Application) updateUserHandler(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromPathValue(r)
	if err != nil {
		writeBadRequest(err, w)
		return
	}

	var req struct {
		Name     *string `json:"name"`
		Email    *string `json:"email"`
		Password *string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeBadRequest(err, w)
		return
	}

	v := NewValidator()
	v.Check(req.Name != nil || req.Email != nil || req.Password != nil, "name, email or password", "must be provided")
	if req.Name != nil {
		v.CheckUsername(*req.Name)
	}
	if req.Email != nil {
		v.CheckEmail(*req.Email)
	}
	if req.Password != nil {
		v.CheckPassword(*req.Password)
	}

	if v.HasError() {
		writeValidatorErrors(v, w)
		return
	}

	u := getUserFromRequest(r)
	if u == nil {
		writeServerError(w)
		return
	}

	if u.ID != int64(id) {
		writeForbidden(w)
		return
	}

	if req.Name != nil {
		u.Name = *req.Name
	}

	if req.Email != nil {
		u.Email = *req.Email
	}

	if req.Password != nil {
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			writeServerError(w)
			return
		}
		u.PasswordHash = passwordHash
	}

	err = app.storage.UpdateUser(u)
	if err != nil {
		writeServerError(w)
		return
	}
	res := map[string]any{
		"user": u,
	}
	writeOK(res, w)
}

func (app *Application) deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromPathValue(r)
	if err != nil {
		writeBadRequest(err, w)
		return
	}
	u := getUserFromRequest(r)
	if u == nil {
		writeServerError(w)
		return
	}
	if id != int(u.ID) {
		writeForbidden(w)
		return
	}
	err = app.storage.DeleteUser(u)
	if err != nil {
		writeServerError(w)
		return
	}
	res := map[string]any{
		"message": "user deleted successfully",
	}
	writeOK(res, w)
}

func (app *Application) createAuthenticationTokenHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	err := readJSON(r, &req)
	if err != nil {
		writeError(err, http.StatusBadRequest, w)
		return
	}

	v := NewValidator()
	v.CheckEmail(req.Email)
	v.CheckPassword(req.Password)
	if v.HasError() {
		writeError(v, http.StatusBadRequest, w)
		return
	}

	u, err := app.storage.GetUserByEmail(req.Email)
	if err != nil {
		writeError(err, http.StatusInternalServerError, w)
		return
	}

	if u == nil {
		writeError(errors.New("invalid credentials"), http.StatusUnauthorized, w)
		return
	}

	err = bcrypt.CompareHashAndPassword(u.PasswordHash, []byte(req.Password))
	if err != nil {
		writeError(errors.New("invalid credentials"), http.StatusUnauthorized, w)
		return
	}

	token, err := app.storage.CreateToken(u.ID, 24*time.Hour, ScopeAuthentication)
	if err != nil {
		writeServerError(w)
		return
	}

	writeJSON(token, http.StatusCreated, w)
}

func (app *Application) createUserActivationTokenHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	err := readJSON(r, &req)
	if err != nil {
		writeBadRequest(err, w)
		return
	}

	v := NewValidator()
	v.CheckEmail(req.Email)
	if v.HasError() {
		writeValidatorErrors(v, w)
		return
	}

	u, err := app.storage.GetUserByEmail(req.Email)
	if err != nil {
		writeServerError(w)
		return
	}

	if u == nil {
		writeBadRequest(errors.New("invalid email"), w)
		return
	}

	if u.IsActivated {
		writeError(errors.New("user is already activated"), http.StatusConflict, w)
		return
	}

	token, err := app.storage.CreateToken(u.ID, 5*time.Minute, ScopeActivation)
	if err != nil {
		writeServerError(w)
		return
	}

	go func(email string, token Token) {
		tmpl, err := template.ParseFS(templates, "templates/*.gotmpl")
		if err != nil {
			log.Println(err)
			return
		}
		err = app.mailer.Send(email, tmpl, map[string]any{"token": token.Text})
		if err != nil {
			log.Println(err)
		}
	}(req.Email, *token)

	res := map[string]any{
		"message": fmt.Sprintf("an activation token was sent to email %s", req.Email),
	}
	writeJSON(res, http.StatusCreated, w)
}

func (app *Application) activateUserHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := readJSON(r, &req); err != nil {
		writeBadRequest(err, w)
		return
	}
	u, err := app.storage.GetUserFromToken(req.Token, ScopeActivation)
	if err != nil {
		writeServerError(w)
		return
	}
	if u == nil {
		writeBadRequest(errors.New("invalid token"), w)
		return
	}
	u.IsActivated = true
	err = app.storage.UpdateUser(u)
	if err != nil {
		writeServerError(w)
		return
	}
	res := map[string]any{
		"message": "user activated",
	}
	writeOK(res, w)
}

func (app *Application) createProductHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Price       decimal.Decimal `json:"price"`
		Quantity    int64           `json:"quantity"`
	}

	if err := readJSON(r, &req); err != nil {
		writeBadRequest(err, w)
		return
	}

	v := NewValidator()
	v.Check(req.Name != "", "name", "must be provided")
	v.Check(len(req.Name) <= 50, "name", "must not be more than 50 characters")
	v.Check(req.Description != "", "description", "must be provided")
	v.Check(req.Price.GreaterThan(decimal.NewFromInt(0)), "price", "must be greater than zero")
	v.Check(req.Quantity >= 0, "quantity", "must be greater than or equal zero")

	if v.HasError() {
		writeValidatorErrors(v, w)
		return
	}

	u := getUserFromRequest(r)
	if u == nil {
		writeServerError(w)
		return
	}

	p, err := app.storage.CreateProduct(req.Name, req.Description, req.Price, req.Quantity)
	if err != nil {
		writeServerError(w)
		return
	}
	res := map[string]any{
		"product": p,
	}
	writeJSON(res, http.StatusCreated, w)
}

func (app *Application) getProductHandler(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromPathValue(r)
	if err != nil {
		writeBadRequest(err, w)
		return
	}
	p, err := app.storage.GetProductByID(int64(id))
	if err != nil {
		writeServerError(w)
		return
	}
	if p == nil {
		writeNotFound(w)
		return
	}
	res := map[string]any{
		"product": p,
	}
	writeOK(res, w)
}

func (app *Application) getProductsHandler(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	name := query.Get("name")
	description := query.Get("description")

	sort := query.Get("sort")
	if sort == "" {
		sort = "id"
	}

	minPrice := decimal.Zero
	minPriceStr := query.Get("min_price")
	if minPriceStr != "" {
		v, err := decimal.NewFromString(minPriceStr)
		if err != nil {
			writeError(err, http.StatusBadRequest, w)
			return
		}
		minPrice = v
	}

	maxPrice := decimal.NewFromFloat(math.MaxFloat64)
	maxPriceStr := query.Get("max_price")
	if maxPriceStr != "" {
		v, err := decimal.NewFromString(maxPriceStr)
		if err != nil {
			writeError(err, http.StatusBadRequest, w)
			return
		}
		maxPrice = v
	}

	page := 1
	pageStr := query.Get("page")
	if pageStr != "" {
		v, err := strconv.Atoi(pageStr)
		if err != nil {
			writeError(err, http.StatusBadRequest, w)
			return
		}
		page = v
	}
	pageSize := 5
	pageSizeStr := query.Get("page_size")
	if pageSizeStr != "" {
		v, err := strconv.Atoi(pageSizeStr)
		if err != nil {
			writeError(err, http.StatusBadRequest, w)
			return
		}
		page = v
	}

	v := NewValidator()
	v.Check(minPrice.GreaterThanOrEqual(decimal.Zero), "min_price", "must be greater than zero or equal zero")
	v.Check(maxPrice.GreaterThanOrEqual(decimal.Zero), "max_price", "must be greater than zero or equal zero")
	v.Check(maxPrice.GreaterThanOrEqual(minPrice), "max_price", `must be greater than or equal "min_price"`)
	v.Check(page > 0, "page", "must be greater than zero")
	v.Check(page <= 10_000_000, "page", "must be less than or equal to 10_000_000")
	v.Check(pageSize > 0, "page_size", "must be greater than zero")
	v.Check(pageSize <= 100, "page_size", "must be less than or equal to 100")
	sortOptions := []string{"id", "-id", "name", "-name", "created_at", "-created_at", "price", "-price"}
	v.Check(slices.Index(sortOptions, sort) != -1, sort, "search option is not supported")

	if v.HasError() {
		writeValidatorErrors(v, w)
		return
	}

	products, total, err := app.storage.GetProducts(name, description, sort, minPrice, maxPrice, page, pageSize)
	if err != nil {
		writeServerError(w)
		return
	}
	res := map[string]any{
		"product": products,
		"total":   total,
	}
	writeOK(res, w)
}

func (app *Application) updateProductHandler(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromPathValue(r)
	if err != nil {
		writeBadRequest(err, w)
		return
	}
	var req struct {
		Name        *string          `json:"name"`
		Description *string          `json:"description"`
		Price       *decimal.Decimal `json:"price"`
		Quantity    *int64           `json:"quantity"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(err, http.StatusBadRequest, w)
		return
	}

	v := NewValidator()
	if req.Name != nil {
		v.Check(*req.Name != "", "name", "must be provided")
		v.Check(len(*req.Name) <= 50, "name", "must not be more than 50 characters")
	}
	if req.Description != nil {
		v.Check(*req.Description != "", "description", "must be provided")
	}
	if req.Price != nil {
		v.Check(req.Price.GreaterThan(decimal.NewFromInt(0)), "price", "must be greater than zero")
	}
	if req.Quantity != nil {
		v.Check(*req.Quantity >= 0, "quantity", "must be greater than or equal zero")
	}
	if v.HasError() {
		writeValidatorErrors(v, w)
		return
	}

	u := getUserFromRequest(r)
	if u == nil {
		writeServerError(w)
		return
	}

	p, err := app.storage.GetProductByID(int64(id))
	if err != nil {
		writeServerError(w)
		return
	}
	if p == nil {
		writeNotFound(w)
		return
	}
	if req.Name != nil {
		p.Name = *req.Name
	}
	if req.Description != nil {
		p.Description = *req.Description
	}
	if req.Price != nil {
		p.Price = *req.Price
	}
	if req.Quantity != nil {
		p.Quantity = *req.Quantity
	}
	err = app.storage.UpdateProduct(p)
	if err != nil {
		writeServerError(w)
		return
	}
	res := map[string]any{
		"product": p,
	}
	writeOK(res, w)
}

func (app *Application) deleteProductHandler(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromPathValue(r)
	if err != nil {
		writeBadRequest(err, w)
		return
	}

	u := getUserFromRequest(r)
	if u == nil {
		writeServerError(w)
		return
	}

	p, err := app.storage.GetProductByID(int64(id))
	if err != nil {
		writeServerError(w)
		return
	}
	if p == nil {
		writeNotFound(w)
		return
	}
	err = app.storage.DeleteProduct(p)
	if err != nil {
		writeServerError(w)
		return
	}
	res := map[string]any{
		"message": "resource deleted successfully",
	}
	writeOK(res, w)
}

func (app *Application) createCartItemHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID int64 `json:"product_id"`
		Quantity  int64 `json:"Quantity"`
	}
	if err := readJSON(r, &req); err != nil {
		writeBadRequest(err, w)
		return
	}

	v := NewValidator()
	v.Check(req.ProductID > 0, "product_id", "must be greater than zero")
	v.Check(req.Quantity > 0, "quantity", "must be greater than zero")

	if v.HasError() {
		writeValidatorErrors(v, w)
		return
	}

	u := getUserFromRequest(r)
	if u == nil {
		writeServerError(w)
		return
	}

	p, err := app.storage.GetProductByID(req.ProductID)
	if err != nil {
		writeServerError(w)
		return
	}

	if p == nil {
		writeNotFound(w)
		return
	}

	if p.Quantity < req.Quantity {
		req.Quantity = p.Quantity
	}

	if req.Quantity == 0 {
		writeError(fmt.Errorf("product id %d is out of stock", req.ProductID), http.StatusBadRequest, w)
		return
	}

	cartItem, err := app.storage.CreateCartItem(req.ProductID, u.ID, req.Quantity)
	if err != nil {
		writeServerError(w)
		return
	}

	res := map[string]any{
		"item": cartItem,
	}
	writeJSON(res, http.StatusCreated, w)
}

func (app *Application) getCartItem(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromPathValue(r)
	if err != nil {
		writeBadRequest(err, w)
		return
	}
	u := getUserFromRequest(r)
	if u == nil {
		writeServerError(w)
		return
	}
	item, err := app.storage.GetCartItemById(int64(id))
	if err != nil {
		writeServerError(w)
		return
	}
	if item == nil {
		writeNotFound(w)
		return
	}
	if item.UserID != u.ID {
		writeForbidden(w)
		return
	}
	res := map[string]any{
		"item": item,
	}
	writeOK(res, w)
}

func (app *Application) getCartItems(w http.ResponseWriter, r *http.Request) {
	u := getUserFromRequest(r)
	if u == nil {
		writeServerError(w)
		return
	}
	items, err := app.storage.GetCartItems(int64(u.ID))
	if err != nil {
		writeServerError(w)
		return
	}
	res := map[string]any{
		"items": items,
	}
	writeOK(res, w)
}

func (app *Application) updateCartItem(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromPathValue(r)
	if err != nil {
		writeBadRequest(err, w)
		return
	}
	var req struct {
		Quantity *int64 `json:"quantity"`
	}
	if err = readJSON(r, &req); err != nil {
		writeError(err, http.StatusBadRequest, w)
		return
	}
	v := NewValidator()
	v.Check(req.Quantity != nil, "quantity", "must be provided")
	v.Check(*req.Quantity > 0, "quantity", "must be greater than zero")
	if v.HasError() {
		writeValidatorErrors(v, w)
		return
	}
	u := getUserFromRequest(r)
	if u == nil {
		writeServerError(w)
		return
	}
	item, err := app.storage.GetCartItemById(int64(id))
	if err != nil {
		writeServerError(w)
		return
	}
	if item == nil {
		writeNotFound(w)
		return
	}
	if item.UserID != u.ID {
		writeForbidden(w)
		return
	}
	item.Quantity = *req.Quantity
	err = app.storage.UpdateCartItem(item)
	if err != nil {
		writeServerError(w)
		return
	}
	res := map[string]any{
		"item": item,
	}
	writeOK(res, w)
}

func (app *Application) deleteCartItem(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromPathValue(r)
	if err != nil {
		writeBadRequest(err, w)
		return
	}

	u := getUserFromRequest(r)
	if u == nil {
		writeServerError(w)
		return
	}
	item, err := app.storage.GetCartItemById(int64(id))
	if err != nil {
		writeServerError(w)
		return
	}
	if item == nil {
		writeNotFound(w)
		return
	}
	if item.UserID != u.ID {
		writeForbidden(w)
		return
	}
	err = app.storage.DeleteCartItem(item)
	if err != nil {
		writeServerError(w)
		return
	}
	res := map[string]any{
		"message": "resource deleted successfully",
	}
	writeOK(res, w)
}

func (app *Application) deleteCartItems(w http.ResponseWriter, r *http.Request) {
	u := getUserFromRequest(r)
	if u == nil {
		writeServerError(w)
		return
	}
	err := app.storage.DeleteCartItems(u.ID)
	if err != nil {
		writeServerError(w)
		return
	}
	res := map[string]any{
		"message": "resources deleted successfully",
	}
	writeOK(res, w)
}

const BalanceTransfer = "BalanceTransfer"

func (app *Application) addToBalanceHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Balance *decimal.Decimal `json:"balance"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(errors.New("bad request"), http.StatusBadRequest, w)
		return
	}

	v := NewValidator()
	v.Check(req.Balance != nil, "balance", "must be provided")
	v.Check(req.Balance.GreaterThan(decimal.Zero), "balance", "must be greater than zero")

	if v.HasError() {
		writeValidatorErrors(v, w)
		return
	}

	u := getUserFromRequest(r)
	if u == nil {
		writeServerError(w)
		return
	}

	lineItems := make([]*stripe.CheckoutSessionLineItemParams, 1)
	price, exact := req.Balance.Mul(decimal.NewFromInt(100)).Float64()
	if !exact {
		writeBadRequest(fmt.Errorf("price %v is not exact", price), w)
		return
	}

	lineItems[0] = &stripe.CheckoutSessionLineItemParams{
		PriceData: &stripe.CheckoutSessionLineItemPriceDataParams{
			Currency: stripe.String("usd"),
			ProductData: &stripe.CheckoutSessionLineItemPriceDataProductDataParams{
				Name: stripe.String(fmt.Sprintf("Add to Account: %s-%s", u.Name, u.Email)),
			},
			UnitAmountDecimal: stripe.Float64(price),
		},
		Quantity: stripe.Int64(1),
	}

	params := &stripe.CheckoutSessionParams{
		LineItems:  lineItems,
		Mode:       stripe.String(string(stripe.CheckoutSessionModePayment)),
		SuccessURL: stripe.String("http://localhost:8080/static/success.html"),
		CancelURL:  stripe.String("http://localhost:8080/static/cancel.html"),
		ExpiresAt:  stripe.Int64(time.Now().Add(30 * time.Minute).Unix()),
		Metadata: map[string]string{
			"user_id":          strconv.Itoa(int(u.ID)),
			"balance_transfer": BalanceTransfer,
		},
	}
	s, err := session.New(params)
	if err != nil {
		writeServerError(w)
		return
	}
	res := map[string]any{
		"url": s.URL,
	}
	writeJSON(res, http.StatusCreated, w)
}

func (app *Application) balancesWebhookHandler(w http.ResponseWriter, r *http.Request) {
	const MaxBodyBytes = int64(65536)
	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading request body: %v\n", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	endpointSecret := os.Getenv("STRIPE_WEBHOOK_SECRET_KEY")
	event, err := webhook.ConstructEvent(body, r.Header.Get("Stripe-Signature"), endpointSecret)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error verifying webhook signature: %v\n", err)
		w.WriteHeader(http.StatusBadRequest) // Return a 400 error on a bad signature
		return
	}
	if event.Type == string(stripe.EventTypeCheckoutSessionCompleted) ||
		event.Type == string(stripe.EventTypeCheckoutSessionAsyncPaymentSucceeded) {

		var cs stripe.CheckoutSession
		err = json.Unmarshal(event.Data.Raw, &cs)
		if err != nil {
			log.Printf("Error Pasring webhook JSON: %v\n", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		params := &stripe.CheckoutSessionParams{
			Expand: []*string{
				stripe.String("line_items"),
			},
		}

		s, err := session.Get(cs.ID, params)
		if err != nil {
			log.Printf("Error Getting Session: %v\n", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		items := s.LineItems.Data
		if len(items) < 1 {
			log.Println("bad request: len(items) must be atleast 1")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if s.PaymentStatus != stripe.CheckoutSessionPaymentStatusUnpaid {
			if s.Metadata["balance_transfer"] != BalanceTransfer {
				log.Println("bad request: missing balance_transfer in metadata")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			userID, err := strconv.Atoi(s.Metadata["user_id"])
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			u, err := app.storage.GetUserById(int64(userID))
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if u == nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			amount := decimal.NewFromFloat(items[0].Price.UnitAmountDecimal).Div(decimal.NewFromInt(100))
			transationSignature := fmt.Sprintf("stripe-session-id=%v", cs.ID)
			t, err := app.storage.GetTransationWithSignature(transationSignature)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if t == nil {
				err = app.storage.TransferToUser(u, transationSignature, amount)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}
		}
	}
}

func (app *Application) checkoutHandler(w http.ResponseWriter, r *http.Request) {
	u := getUserFromRequest(r)
	if u == nil {
		writeServerError(w)
		return
	}
	total, orderID, err := app.storage.CheckoutCart(u)
	if err != nil {
		writeError(err, http.StatusConflict, w)
		return
	}
	res := map[string]any{
		"total":    total,
		"order_id": orderID,
	}
	writeOK(res, w)
}

func (app *Application) getOrderHandler(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromPathValue(r)
	if err != nil {
		writeBadRequest(err, w)
		return
	}
	u := getUserFromRequest(r)
	if u == nil {
		writeServerError(w)
		return
	}
	order, err := app.storage.GetOrderByID(int64(id))
	if err != nil {
		writeServerError(w)
		return
	}
	if order == nil {
		writeNotFound(w)
		return
	}
	if order.UserID != u.ID {
		writeForbidden(w)
		return
	}
	items, err := app.storage.GetOrderItems(order.ID)
	if err != nil || items == nil {
		writeServerError(w)
		return
	}
	res := map[string]any{
		"order": order,
		"items": items,
	}
	writeOK(res, w)
}

func (app *Application) getOrdersHandler(w http.ResponseWriter, r *http.Request) {
	u := getUserFromRequest(r)
	if u == nil {
		writeServerError(w)
		return
	}
	orders, err := app.storage.GetOrdersItems(u.ID)
	if err != nil {
		writeServerError(w)
		return
	}
	if orders == nil {
		writeNotFound(w)
		return
	}
	res := map[string]any{
		"orders": orders,
	}
	writeOK(res, w)
}

func (app *Application) updateOrderHandler(w http.ResponseWriter, r *http.Request) {
	id, err := getIDFromPathValue(r)
	if err != nil {
		writeBadRequest(err, w)
		return
	}
	var req struct {
		Operation *string `json:"operation"`
	}
	if err = readJSON(r, &req); err != nil {
		writeError(err, http.StatusBadRequest, w)
		return
	}
	v := NewValidator()
	v.Check(req.Operation != nil, "operation", "must be provided")
	validOperations := []string{"deliver", "cancel"}
	if req.Operation != nil {
		v.Check(slices.Index(validOperations, *req.Operation) != -1, "operation", "unsupported")
	}
	if v.HasError() {
		writeValidatorErrors(v, w)
		return
	}
	u := getUserFromRequest(r)
	if u == nil {
		writeServerError(w)
		return
	}
	order, err := app.storage.GetOrderByID(int64(id))
	if err != nil {
		writeServerError(w)
		return
	}
	if order == nil {
		writeNotFound(w)
		return
	}
	if order.UserID != u.ID {
		writeForbidden(w)
		return
	}
	if order.StatusID != int64(OrderStatusInProgress) {
		writeError(errors.New("invalid operation order is already completed"), http.StatusConflict, w)
		return
	}
	// TODO: we need to make sure user has permissions to update orders
	op := *req.Operation
	switch op {
	case "deliver":
		err = app.storage.DeliverOrder(order)
		if err != nil {
			writeServerError(w)
			return
		}
		res := map[string]any{"message": "delivered"}
		writeOK(res, w)
	case "cancel":
		total, err := app.storage.CancelOrder(order)
		if err != nil {
			writeServerError(w)
			return
		}
		res := map[string]any{"message": "cancelled", "total": total}
		writeOK(res, w)
	}
}
