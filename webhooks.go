package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/google/uuid"
	"github.com/luckysal/chirpy/internal/auth"
)

// handle webhooks requests
func (cfg *apiConfig) handlerWebhooks(w http.ResponseWriter, r *http.Request) {
	// format for webhooks request
	type webhooksRequest struct {
		Event string `json:"event"`
		Data  struct {
			UserID uuid.UUID `json:"user_id"`
		} `json:"data"`
	}

	// decode request
	var req webhooksRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// check for authorization
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil || apiKey != cfg.polkaKey{
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// handle event
	switch req.Event {
	// upgrade user to "Chirpy Red"
	case "user.upgraded":
		_, err := cfg.queries.SetUserRed(r.Context(), req.Data.UserID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				w.WriteHeader(http.StatusNotFound)
				return
			} else {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
		return

	// ignore undefined requests
	default:
		w.WriteHeader(http.StatusNoContent)
		return
	}
}
