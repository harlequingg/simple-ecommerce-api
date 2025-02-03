package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"

	"golang.org/x/crypto/bcrypt"
)

func (app *Application) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	res := struct {
		Version     string `json:"version"`
		Environment string `json:"env"`
	}{Version: version, Environment: app.config.environment}
	writeJSON(res, w)
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
	writeJSON(u, w)
}

func (app *Application) getUserHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(err, http.StatusBadRequest, w)
		return
	}
	u, err := app.storage.GetUserById(int64(id))
	if err != nil {
		writeError(err, http.StatusInternalServerError, w)
		return
	}
	if u == nil {
		writeError(errors.New("not found"), http.StatusNotFound, w)
		return
	}
	writeJSON(u, w)
}

func (app *Application) updateUserHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(err, http.StatusBadRequest, w)
		return
	}

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

	u, err := app.storage.GetUserById(int64(id))
	if err != nil {
		writeError(err, http.StatusInternalServerError, w)
		return
	}
	if u == nil {
		writeError(errors.New("not found"), http.StatusNotFound, w)
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
			writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
			return
		}
		u.PasswordHash = passwordHash
	}

	err = app.storage.UpdateUser(u)
	if err != nil {
		log.Println(err)
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
		return
	}
	writeJSON(u, w)
}

func (app *Application) deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		writeError(err, http.StatusBadRequest, w)
		return
	}
	u, err := app.storage.GetUserById(int64(id))
	if err != nil {
		writeError(err, http.StatusInternalServerError, w)
		return
	}
	if u == nil {
		writeError(errors.New("not found"), http.StatusNotFound, w)
		return
	}
	err = app.storage.DeleteUser(u)
	if err != nil {
		writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
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

func writeJSON(src any, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
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
