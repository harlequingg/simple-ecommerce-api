package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
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

func (app *Application) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	res := struct {
		Version     string `json:"version"`
		Environment string `json:"env"`
	}{Version: version, Environment: app.config.environment}
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
		writeError(v, http.StatusBadRequest, w)
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(err, http.StatusInternalServerError, w)
		return
	}

	u, err := app.storage.CreateUser(req.Name, req.Email, passwordHash)
	if err != nil {
		writeError(err, http.StatusInternalServerError, w)
		return
	}
	writeJSON(u, http.StatusCreated, w)
}

func (app *Application) getUserHandler(w http.ResponseWriter, r *http.Request) {
	u := getUserFromRequest(r)
	writeJSON(u, http.StatusOK, w)
}

func (app *Application) updateUserHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name     *string `json:"name"`
		Email    *string `json:"email"`
		Password *string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(err, http.StatusBadRequest, w)
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
		writeError(v, http.StatusBadRequest, w)
		return
	}

	u := getUserFromRequest(r)

	if req.Name != nil {
		u.Name = *req.Name
	}

	if req.Email != nil {
		u.Email = *req.Email
	}

	if req.Password != nil {
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
			return
		}
		u.PasswordHash = passwordHash
	}

	err := app.storage.UpdateUser(u)
	if err != nil {
		log.Println(err)
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	writeJSON(u, http.StatusOK, w)
}

func (app *Application) deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	u := getUserFromRequest(r)
	err := app.storage.DeleteUser(u)
	if err != nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
	}
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
		log.Println(err)
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}

	writeJSON(token, http.StatusCreated, w)
}

func (app *Application) createProductHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Price       decimal.Decimal `json:"price"`
		Quantity    int64           `json:"quantity"`
	}
	err := readJSON(r, &req)
	if err != nil {
		writeError(err, http.StatusBadRequest, w)
		return
	}

	v := NewValidator()
	v.Check(req.Name != "", "name", "must be provided")
	v.Check(len(req.Name) <= 50, "name", "must not be more than 50 characters")
	v.Check(req.Description != "", "description", "must be provided")
	v.Check(req.Price.GreaterThan(decimal.NewFromInt(0)), "price", "must be greater than zero")
	v.Check(req.Quantity >= 0, "quantity", "must be greater than or equal zero")

	if v.HasError() {
		writeError(v, http.StatusBadRequest, w)
		return
	}

	u := getUserFromRequest(r)
	if u == nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}

	p, err := app.storage.CreateProduct(req.Name, req.Description, req.Price, req.Quantity)
	if err != nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	writeJSON(p, http.StatusCreated, w)
}

func (app *Application) getProductHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(err, http.StatusBadRequest, w)
		return
	}
	if id < 0 {
		writeError(errors.New("id must be a positive integer"), http.StatusBadRequest, w)
		return
	}
	p, err := app.storage.GetProductByID(int64(id))
	if err != nil {
		log.Println(err)
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	if p == nil {
		writeError(errors.New("not found"), http.StatusNotFound, w)
		return
	}
	writeJSON(p, http.StatusOK, w)
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
		writeError(v, http.StatusBadRequest, w)
		return
	}

	products, total, err := app.storage.GetProducts(name, description, sort, minPrice, maxPrice, page, pageSize)
	if err != nil {
		log.Println(err)
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	writeJSON(map[string]any{"products": products, "total": total}, http.StatusOK, w)
}

func (app *Application) updateProductHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(err, http.StatusBadRequest, w)
		return
	}
	if id < 0 {
		writeError(errors.New("id must be a positive integer"), http.StatusBadRequest, w)
		return
	}
	var req struct {
		Name        *string          `json:"name"`
		Description *string          `json:"description"`
		Price       *decimal.Decimal `json:"price"`
		Quantity    *int64           `json:"quantity"`
	}
	err = readJSON(r, &req)
	if err != nil {
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
		writeError(v, http.StatusBadRequest, w)
		return
	}

	u := getUserFromRequest(r)
	if u == nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}

	p, err := app.storage.GetProductByID(int64(id))
	if err != nil {
		log.Println(err)
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	if p == nil {
		writeError(errors.New("not found"), http.StatusNotFound, w)
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
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	writeJSON(p, http.StatusOK, w)
}

func (app *Application) deleteProductHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(err, http.StatusBadRequest, w)
		return
	}

	if id < 0 {
		writeError(errors.New("id must be a positive integer"), http.StatusBadRequest, w)
		return
	}

	u := getUserFromRequest(r)
	if u == nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}

	p, err := app.storage.GetProductByID(int64(id))
	if err != nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	if p == nil {
		writeError(errors.New("not found"), http.StatusNotFound, w)
		return
	}
	err = app.storage.DeleteProduct(p)
	if err != nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	writeJSON(map[string]any{"message": "resource deleted successfully"}, http.StatusOK, w)
}

func (app *Application) createCartItemHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ProductID int64 `json:"product_id"`
		Quantity  int64 `json:"Quantity"`
	}
	err := readJSON(r, &req)
	if err != nil {
		writeError(err, http.StatusBadRequest, w)
		return
	}

	v := NewValidator()
	v.Check(req.ProductID > 0, "product_id", "must be greater than zero")
	v.Check(req.Quantity > 0, "quantity", "must be greater than zero")

	if v.HasError() {
		writeError(v, http.StatusBadRequest, w)
		return
	}

	u := getUserFromRequest(r)
	if u == nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}

	p, err := app.storage.GetProductByID(req.ProductID)
	if err != nil {
		log.Println(err)
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}

	if p == nil {
		writeError(fmt.Errorf("product with id: %d doesn't exist", req.ProductID), http.StatusInternalServerError, w)
		return
	}

	if p.Quantity < req.Quantity {
		req.Quantity = p.Quantity
	}

	if req.Quantity == 0 {
		writeError(fmt.Errorf("product with id: %d is out of stock", req.ProductID), http.StatusInternalServerError, w)
		return
	}

	cartItem, err := app.storage.CreateCartItem(req.ProductID, u.ID, req.Quantity)
	if err != nil {
		log.Println(err)
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}

	writeJSON(cartItem, http.StatusCreated, w)
}

func (app *Application) getCartItem(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(err, http.StatusBadRequest, w)
		return
	}
	if id < 0 {
		writeError(errors.New("id must be a positive integer"), http.StatusBadRequest, w)
		return
	}
	u := getUserFromRequest(r)
	if u == nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	item, err := app.storage.GetCartItemById(int64(id))
	if err != nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	if item == nil {
		writeError(errors.New("not found"), http.StatusNotFound, w)
		return
	}
	if item.UserID != u.ID {
		writeError(errors.New("access denied"), http.StatusForbidden, w)
		return
	}
	writeJSON(item, http.StatusOK, w)
}

func (app *Application) getCartItems(w http.ResponseWriter, r *http.Request) {
	u := getUserFromRequest(r)
	if u == nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	items, err := app.storage.GetCartItems(int64(u.ID))
	if err != nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	writeJSON(map[string]any{"items": items}, http.StatusOK, w)
}

func (app *Application) updateCartItem(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(err, http.StatusBadRequest, w)
		return
	}
	if id < 0 {
		writeError(errors.New("id must be a positive integer"), http.StatusBadRequest, w)
		return
	}
	var req struct {
		Quantity *int64 `json:"quantity"`
	}
	err = readJSON(r, &req)
	if err != nil {
		writeError(err, http.StatusBadRequest, w)
		return
	}
	v := NewValidator()
	v.Check(req.Quantity != nil, "quantity", "must be provided")
	v.Check(*req.Quantity > 0, "quantity", "must be greater than zero")
	if v.HasError() {
		writeError(v, http.StatusBadRequest, w)
		return
	}
	u := getUserFromRequest(r)
	if u == nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	item, err := app.storage.GetCartItemById(int64(id))
	if err != nil {
		log.Println(err)
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	if item == nil {
		writeError(errors.New("not found"), http.StatusNotFound, w)
		return
	}
	if item.UserID != u.ID {
		writeError(errors.New("access denied"), http.StatusForbidden, w)
		return
	}
	item.Quantity = *req.Quantity
	err = app.storage.UpdateCartItem(item)
	if err != nil {
		log.Println(err)
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	writeJSON(item, http.StatusOK, w)
}

func (app *Application) deleteCartItem(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(err, http.StatusBadRequest, w)
		return
	}
	if id < 0 {
		writeError(errors.New("id must be a positive integer"), http.StatusBadRequest, w)
		return
	}

	u := getUserFromRequest(r)
	if u == nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	item, err := app.storage.GetCartItemById(int64(id))
	if err != nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	if item == nil {
		writeError(errors.New("not found"), http.StatusNotFound, w)
		return
	}
	if item.UserID != u.ID {
		writeError(errors.New("access denied"), http.StatusForbidden, w)
		return
	}
	err = app.storage.DeleteCartItem(item)
	if err != nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	writeJSON(map[string]any{"message": "resource deleted successfully"}, http.StatusOK, w)
}

func (app *Application) deleteCartItems(w http.ResponseWriter, r *http.Request) {
	u := getUserFromRequest(r)
	if u == nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	err := app.storage.DeleteCartItems(u.ID)
	if err != nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	writeJSON(map[string]any{"message": "resources deleted successfully"}, http.StatusOK, w)
}

const BalanceTransfer = "BalanceTransfer"

func (app *Application) addToBalanceHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Balance *decimal.Decimal `json:"balance"`
	}
	err := readJSON(r, &req)
	if err != nil {
		writeError(errors.New("bad request"), http.StatusBadRequest, w)
		return
	}

	v := NewValidator()
	v.Check(req.Balance != nil, "balance", "must be provided")
	v.Check(req.Balance.GreaterThan(decimal.Zero), "balance", "must be greater than zero")

	if v.HasError() {
		writeError(v, http.StatusBadRequest, w)
		return
	}

	u := getUserFromRequest(r)
	if u == nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}

	lineItems := make([]*stripe.CheckoutSessionLineItemParams, 1)
	price, exact := req.Balance.Mul(decimal.NewFromInt(100)).Float64()
	if !exact {
		writeError(errors.New("bad request"), http.StatusBadRequest, w)
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
		log.Println(err)
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	writeJSON(map[string]any{"url": s.URL}, http.StatusCreated, w)
}

func (app *Application) checkoutHandler(w http.ResponseWriter, r *http.Request) {
	u := getUserFromRequest(r)
	if u == nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	total, err := app.storage.CheckoutCart(u)
	if err != nil {
		log.Println(err)
		writeError(err, http.StatusForbidden, w)
		return
	}
	writeJSON(map[string]any{"total": total}, http.StatusOK, w)
}

func (app *Application) webhookHandler(w http.ResponseWriter, r *http.Request) {
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
			log.Println("bad request: len(items) must be atleast1")
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
				log.Println("bad request: ", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			u, err := app.storage.GetUserById(int64(userID))
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			if u == nil {
				log.Println("user doesn't exist")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			amount := decimal.NewFromFloat(items[0].Price.UnitAmountDecimal).Div(decimal.NewFromInt(100))
			u.Balance = u.Balance.Add(amount)
			// TODO: We should record this in the database because we might get the same exact request multiple times for the same user...
			err = app.storage.UpdateUser(u)
			if err != nil {
				log.Println(err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			log.Println("success")
		}
	}
}

func readJSON(r *http.Request, dst any) error {
	err := json.NewDecoder(r.Body).Decode(dst)
	if err != nil {
		log.Println(err)
		return err
	}
	return nil
}

func writeJSON(src any, status int, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	var b bytes.Buffer
	err := json.NewEncoder(&b).Encode(src)
	if err != nil {
		log.Println(err)
		return
	}
	w.Write(b.Bytes())
}

func writeError(err error, status int, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	data := map[string]any{"error": err.Error()}
	json.NewEncoder(w).Encode(data)
}
