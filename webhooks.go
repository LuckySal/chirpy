package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/google/uuid"
)

func (cfg *apiConfig) handlerWebhooks(w http.ResponseWriter, r *http.Request) {
	type webhooksRequest struct {
		Event string `json:"event"`
		Data  struct {
			UserID uuid.UUID `json:"user_id"`
		} `json:"data"`
	}

	var req webhooksRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if req.Event == "user.upgraded" {
		if err := cfg.queries.SetUserRed(context.Background(), req.Data.UserID); err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}
