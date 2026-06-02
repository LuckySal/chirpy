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
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// check for valid request body
	if user.Email == "" || user.Password == "" {
		log.Println("\"Create user\" request received without valid body")
		respondWithError(w, http.StatusBadRequest, "Include \"email\" and \"password\" in request body", nil)
		return
	}

	// hash password
	pwd, err := auth.HashPassword(user.Password)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
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
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
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

// endpoint login a user
// return access and refresh tokens
func (cfg *apiConfig) handlerLogin(w http.ResponseWriter, r *http.Request) {
	type LoginRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var loginRequest LoginRequest

	// decode login request
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&loginRequest); err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
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
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	// check for password match
	match, err := auth.CheckPasswordHash(loginRequest.Password, user.HashedPassword)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if !match {
		respondWithError(w, http.StatusUnauthorized, "incorrect username or password", nil)
		return
	}

	// generate JWT
	token, err := auth.MakeJWT(user.ID, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "error creating access token", err)
		return
	}

	// generate refresh token
	refreshToken, err := cfg.queries.CreateRefreshToken(
		context.Background(),
		database.CreateRefreshTokenParams{
			Token:  auth.MakeRefreshToken(),
			UserID: user.ID,
		})
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "error generating refresh token", err)
		return
	}

	// respond with user information
	userInfo := struct {
		ID           uuid.UUID `json:"id"`
		CreatedAt    time.Time `json:"created_at"`
		UpdatedAt    time.Time `json:"updated_at"`
		Email        string    `json:"email"`
		Token        string    `json:"token"`
		RefreshToken string    `json:"refresh_token"`
	}{
		ID:           user.ID,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Email:        user.Email,
		Token:        token,
		RefreshToken: refreshToken.Token,
	}
	respondWithJSON(w, http.StatusOK, userInfo)
}

// generate new access token for current user
func (cfg *apiConfig) handlerRefresh(w http.ResponseWriter, r *http.Request) {
	// get refresh token from request header
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid or expired refresh token", err)
		return
	}

	// get user from database
	user, err := cfg.queries.GetUserFromRefreshToken(context.Background(), refreshToken)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid or expired refresh token", err)
		return
	}

	// check refresh token status
	if user.ExpiresAt.Before(time.Now()) || user.RevokedAt.Valid {
		respondWithError(w, http.StatusUnauthorized, "invalid or expired refresh token", err)
		return
	}

	// generate new access token
	accessToken, err := auth.MakeJWT(user.ID, cfg.jwtSecret)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// generate response
	respondWithJSON(
		w,
		http.StatusOK,
		struct {
			AccessToken string `json:"token"`
		}{
			AccessToken: accessToken,
		},
	)
}

// revoke refresh token
func (cfg *apiConfig) handlerRevoke(w http.ResponseWriter, r *http.Request) {
	// get token from request header
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid or expired refresh token", err)
		return
	}

	// revoke refresh token
	if err := cfg.queries.RevokeRefreshToken(context.Background(), refreshToken); err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid or expired refresh token", err)
		return
	}

	// success
	w.WriteHeader(http.StatusNoContent)
}
