package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/shopspring/decimal"
	"github.com/stripe/stripe-go/v81"
	"github.com/stripe/stripe-go/v81/checkout/session"
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
		Amount      int             `json:"amount"`
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
	v.Check(req.Amount >= 0, "amount", "must be greater than or equal zero")

	if v.HasError() {
		writeError(v, http.StatusBadRequest, w)
		return
	}

	u := getUserFromRequest(r)
	if u == nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}

	p, err := app.storage.CreateProduct(req.Name, req.Description, req.Price, int32(req.Amount))
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
		Amount      *int             `json:"amount"`
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
	if req.Amount != nil {
		v.Check(*req.Amount >= 0, "amount", "must be greater than or equal zero")
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
	if req.Amount != nil {
		p.Amount = int32(*req.Amount)
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
		Amount    int32 `json:"amount"`
	}
	err := readJSON(r, &req)
	if err != nil {
		writeError(err, http.StatusBadRequest, w)
		return
	}

	v := NewValidator()
	v.Check(req.ProductID > 0, "product_id", "must be greater than zero")
	v.Check(req.Amount > 0, "amount", "must be greater than zero")

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

	cartItem, err := app.storage.CreateCartItem(req.ProductID, u.ID, req.Amount)
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
		Amount *int32 `json:"amount"`
	}
	err = readJSON(r, &req)
	if err != nil {
		writeError(err, http.StatusBadRequest, w)
		return
	}
	v := NewValidator()
	v.Check(req.Amount != nil, "amount", "must be provided")
	v.Check(*req.Amount > 0, "amount", "must be greater than zero")
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
	item.Amount = *req.Amount
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

func (app *Application) checkoutHandler(w http.ResponseWriter, r *http.Request) {
	u := getUserFromRequest(r)
	if u == nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	items, err := app.storage.GetCartItemsForCheckout(u.ID)
	if err != nil {
		log.Println(err)
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	if len(items) == 0 {
		writeError(errors.New("shopping cart is empty"), http.StatusBadRequest, w)
		return
	}
	log.Println(items)
	lineItems := make([]*stripe.CheckoutSessionLineItemParams, len(items))
	for idx, item := range items {
		price, _ := item.Product.Price.Mul(decimal.NewFromInt(100)).Float64()
		lineItems[idx] = &stripe.CheckoutSessionLineItemParams{
			PriceData: &stripe.CheckoutSessionLineItemPriceDataParams{
				Currency: stripe.String("usd"),
				ProductData: &stripe.CheckoutSessionLineItemPriceDataProductDataParams{
					Name: stripe.String(item.Product.Name),
				},
				UnitAmountDecimal: stripe.Float64(price),
			},
			Quantity: stripe.Int64(int64(min(item.Amount, item.Product.Amount))),
		}
	}
	params := &stripe.CheckoutSessionParams{
		LineItems:  lineItems,
		Mode:       stripe.String(string(stripe.CheckoutSessionModePayment)),
		SuccessURL: stripe.String("http://localhost:8080/static/success.html"),
		CancelURL:  stripe.String("http://localhost:8080/static/cancel.html"),
	}

	s, err := session.New(params)
	if err != nil {
		log.Println(err)
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}

	writeJSON(map[string]any{"url": s.URL}, http.StatusCreated, w)
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
