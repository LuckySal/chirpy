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

// endpoint create a new user
// requires unique email address
func (cfg *apiConfig) handlerCreateUser(w http.ResponseWriter, r *http.Request) {
	// decode request
	type newUser struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var user newUser
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&user); err != nil {
		log.Printf("Error decoding request body: %v", err)
		respondWithError(w, http.StatusInternalServerError, "Error decoding request body", err)
		return
	}

	// check for valid request body
	if user.Email == "" || user.Password == "" {
		log.Printf("Create user request received without valid body")
		respondWithError(w, http.StatusBadRequest, "Include \"email\" and \"password\" in request body", nil)
		return
	}

	// hash password
	pwd, err := auth.HashPassword(user.Password)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error hashing password", err)
		return
	}

	// create database entry for user
	params := database.CreateUserParams{Email: user.Email, HashedPassword: pwd}
	result, err := cfg.queries.CreateUser(context.Background(), params)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			respondWithError(w, http.StatusBadRequest, "Email taken, use a different email", err)
			return
		}
		respondWithError(w, http.StatusInternalServerError, "Error creating user", err)
		return
	}

	// return success message
	log.Printf("User created with ID: %v", result.ID)
	type Response struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
	}
	response := Response{
		ID:        result.ID,
		CreatedAt: result.CreatedAt,
		UpdatedAt: result.UpdatedAt,
		Email:     result.Email,
	}
	respondWithJSON(w, http.StatusCreated, response)
}

func (cfg *apiConfig) handlerLogin(w http.ResponseWriter, r *http.Request) {
	type LoginRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Expires  int    `json:"expires_in_seconds"`
	}
	var loginRequest LoginRequest

	// decode login request
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&loginRequest); err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error decoding json", err)
		return
	}
	if loginRequest.Email == "" || loginRequest.Password == "" {
		respondWithError(w, http.StatusBadRequest, "requires username and password", nil)
		return
	}

	// retrieve user from database
	user, err := cfg.queries.GetUserByEmail(context.Background(), loginRequest.Email)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			respondWithError(w, http.StatusUnauthorized, "incorrect username or password", err)
		} else {
			respondWithError(w, http.StatusInternalServerError, "error fetching users", err)
		}
		return
	}

	// check for password match
	match, err := auth.CheckPasswordHash(loginRequest.Password, user.HashedPassword)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "error hashing password", err)
		return
	}
	if !match {
		respondWithError(w, http.StatusUnauthorized, "incorrect username or password", nil)
		return
	}

	// generate JWT
	var expiresIn time.Duration
	if 0 < loginRequest.Expires && loginRequest.Expires < 3600 {
		expiresIn = time.Duration(loginRequest.Expires) * time.Second
	} else {
		expiresIn = time.Hour
	}
	token, err := auth.MakeJWT(user.ID, cfg.jwtSecret, expiresIn)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "error creating JWT", err)
	}

	// respond with user information
	userInfo := struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
		Token     string    `json:"token"`
	}{
		ID:        user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
		Token:     token,
	}
	respondWithJSON(w, http.StatusOK, userInfo)
}
