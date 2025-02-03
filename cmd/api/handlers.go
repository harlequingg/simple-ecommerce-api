package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
)

func (app *Application) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	res := struct {
		Version     string `json:"version"`
		Environment string `json:"env"`
	}{Version: version, Environment: app.config.environment}
	writeJSON(res, w)
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
