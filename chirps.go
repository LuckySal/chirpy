package main

import (
	"context"
	"encoding/json"
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
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
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
	result, err := cfg.queries.CreateChirp(context.Background(), params)
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
func (cfg *apiConfig) handlerGetChirps(w http.ResponseWriter, _ *http.Request) {
	dbChirps, err := cfg.queries.GetChirps(context.Background())
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Failed to load chirps from database", err)
		return
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
	dbChirp, err := cfg.queries.GetChirpByID(context.Background(), chirpID)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
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
