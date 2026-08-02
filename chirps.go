package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/luckysal/chirpy/internal/auth"
	"github.com/luckysal/chirpy/internal/database"
)

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

// post a chirp to the database
// requires json body and user_id
func (cfg *apiConfig) handlerPostChirp(w http.ResponseWriter, r *http.Request) {
	// validate JWT
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid or expired access token", err)
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid or expired access token", err)
		return
	}

	// constants
	const MAX_CHIRP_LENGTH = 140
	BANNED_WORDS := map[string]struct{}{
		"kerfuffle": {},
		"sharbert":  {},
		"fornax":    {},
	}

	// decode request body
	type input struct {
		Body string `json:"body"`
	}
	var newChirp input
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&newChirp); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// validate request body
	if newChirp.Body == "" {
		respondWithError(w, http.StatusBadRequest, "Chirps require a body", nil)
		return
	}
	if len(newChirp.Body) > MAX_CHIRP_LENGTH {
		respondWithError(w, http.StatusBadRequest, "Chirp is too long", nil)
		return
	}

	// clean body
	cleanedBody := cleanMessage(newChirp.Body, BANNED_WORDS)
	params := database.CreateChirpParams{
		Body:   cleanedBody,
		UserID: userID,
	}

	// save to database
	result, err := cfg.queries.CreateChirp(r.Context(), params)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// success message and response
	log.Printf("Chirp posted with id: %v", result.ID)
	resp := Chirp{
		ID:        result.ID,
		CreatedAt: result.CreatedAt,
		UpdatedAt: result.UpdatedAt,
		Body:      result.Body,
		UserID:    result.UserID,
	}
	respondWithJSON(w, http.StatusCreated, resp)
}

// get all chirps from database
func (cfg *apiConfig) handlerGetChirps(w http.ResponseWriter, r *http.Request) {
	userID := r.URL.Query().Get("author_id")

	dbChirps := []database.Chirp{}
	var err error

	if userID != "" {
		parsedID, err := uuid.Parse(userID)
		if err != nil {
			respondWithError(w, http.StatusBadRequest, "invalid author_id", err)
			return
		}
		dbChirps, err = cfg.queries.GetChirpsByUser(r.Context(), parsedID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				respondWithError(w, http.StatusNotFound, "no results", err)
				return
			} else {
				respondWithError(w, http.StatusInternalServerError, "Failed to load chirps from database", err)
				return
			}
		}
	} else {
		dbChirps, err = cfg.queries.GetChirps(r.Context())
		if err != nil {
			respondWithError(w, http.StatusInternalServerError, "Failed to load chirps from database", err)
			return
		}
	}

	// convert to json formatted structs
	chirps := []Chirp{}
	for _, dbChirp := range dbChirps {
		chirps = append(chirps, Chirp{
			ID:        dbChirp.ID,
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
			Body:      dbChirp.Body,
			UserID:    dbChirp.UserID,
		})
	}

	// success message and response
	log.Printf("Returning %d chirps", len(chirps))
	respondWithJSON(w, http.StatusOK, chirps)
}

// get one chirp by chirp ID
func (cfg *apiConfig) handlerGetChirpByID(w http.ResponseWriter, r *http.Request) {
	// parse chirp_id
	chirpID, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid chirp_id", err)
		return
	}

	// retreive chirp from database
	dbChirp, err := cfg.queries.GetChirpByID(r.Context(), chirpID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			respondWithError(w, http.StatusNotFound, "Chirp not found", err)
		} else {
			respondWithError(w, http.StatusInternalServerError, "Error getting chirp", err)
		}
		return
	}

	// success message and response
	chirp := Chirp{
		ID:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserID:    dbChirp.UserID,
	}
	log.Printf("Retreived chirp with id: %v", dbChirp.ID)
	respondWithJSON(w, http.StatusOK, chirp)
}

func (cfg *apiConfig) handlerDeleteChirp(w http.ResponseWriter, r *http.Request) {
	// validate JWT
	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid or expired access token", err)
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid or expired access token", err)
		return
	}

	chirpID, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		respondWithError(w, http.StatusNotFound, "", err)
		return
	}
	chirpToDelete, err := cfg.queries.GetChirpByID(r.Context(), chirpID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "", err)
	}
	if chirpToDelete.UserID != userID {
		respondWithError(w, http.StatusForbidden, "no permission", nil)
		return
	}

	if err = cfg.queries.DeleteChirpByID(r.Context(), chirpToDelete.ID); err != nil {
		respondWithError(w, http.StatusInternalServerError, "error processing request", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// finds banned words in message
// replaces banned words with "****"
// returns new message
func cleanMessage(message string, bannedWords map[string]struct{}) string {
	words := strings.Split(message, " ")
	for i, word := range words {
		loweredWord := strings.ToLower(word)
		if _, ok := bannedWords[loweredWord]; ok {
			words[i] = "****"
		}
	}
	newMessage := strings.Join(words, " ")
	return newMessage
}
