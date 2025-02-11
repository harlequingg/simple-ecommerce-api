package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
)

func getPathValuePositiveInt(r *http.Request, p string) (int, error) {
	v, err := strconv.Atoi(r.PathValue(p))
	if err != nil {
		return 0, fmt.Errorf(`invalid path parameter %q must be a positive integer`, p)
	}
	if v <= 0 {
		return 0, fmt.Errorf(`invalid path parameter %q must be a positive integer`, p)
	}
	return v, nil
}

func getIDFromPathValue(r *http.Request) (int, error) {
	id, err := getPathValuePositiveInt(r, "id")
	if err != nil {
		return 0, err
	}
	return id, nil
}

func readJSON(r *http.Request, dst any) error {
	err := json.NewDecoder(r.Body).Decode(dst)
	if err != nil {
		var synatxErr *json.SyntaxError
		var unmarshalTypeErr *json.UnmarshalTypeError
		var invalidUnmarshalErr *json.InvalidUnmarshalError
		switch {
		case errors.Is(err, io.ErrUnexpectedEOF):
			return fmt.Errorf("body contains malformed JSON")
		case errors.Is(err, io.EOF):
			return fmt.Errorf("body must not empty")
		case errors.As(err, &synatxErr):
			return fmt.Errorf("body contains malformed JSON at character %d", synatxErr.Offset)
		case errors.As(err, &unmarshalTypeErr):
			if unmarshalTypeErr.Field != "" {
				return fmt.Errorf("body contains incorrect JSON type for field %q", unmarshalTypeErr.Field)
			}
			return fmt.Errorf("body contains malformed JSON at character %d", unmarshalTypeErr.Offset)
		case errors.As(err, &invalidUnmarshalErr):
			panic(err)
		default:
			return err
		}
	}
	return nil
}

func writeJSON(src any, status int, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(src)
}

func writeError(err error, status int, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	data := map[string]any{"error": err.Error()}
	json.NewEncoder(w).Encode(data)
}

func writeValidatorErrors(v *Validator, w http.ResponseWriter) {
	res := map[string]any{
		"errors": v.violations,
	}
	writeJSON(res, http.StatusBadRequest, w)
}

func writeOK(res any, w http.ResponseWriter) {
	writeJSON(res, http.StatusOK, w)
}

func writeServerError(w http.ResponseWriter) {
	writeError(errors.New("internal server error"), http.StatusInternalServerError, w)
}

func writeBadRequest(err error, w http.ResponseWriter) {
	writeError(err, http.StatusBadRequest, w)
}

func writeNotFound(w http.ResponseWriter) {
	writeError(errors.New("not found"), http.StatusNotFound, w)
}

func writeForbidden(w http.ResponseWriter) {
	writeError(errors.New("permission denied"), http.StatusForbidden, w)
}

func (app *Application) background(fn func()) {
	app.wg.Add(1)
	go func() {
		defer func() {
			if err := recover(); err != nil {
				log.Println(err)
			}
			app.wg.Done()
		}()
		fn()
	}()
}
