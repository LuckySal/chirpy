package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
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
		w.WriteHeader(http.StatusBadRequest)
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
	result, err := cfg.queries.CreateUser(r.Context(), params)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
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
		ID          uuid.UUID `json:"id"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		Email       string    `json:"email"`
		IsChirpyRed bool      `json:"is_chirpy_red"`
	}
	response := Response{
		ID:          result.ID,
		CreatedAt:   result.CreatedAt,
		UpdatedAt:   result.UpdatedAt,
		Email:       result.Email,
		IsChirpyRed: result.IsChirpyRed,
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
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if loginRequest.Email == "" || loginRequest.Password == "" {
		respondWithError(w, http.StatusBadRequest, "requires username and password", nil)
		return
	}

	// retrieve user from database
	user, err := cfg.queries.GetUserByEmail(r.Context(), loginRequest.Email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
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
		r.Context(),
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
		IsChirpyRed  bool      `json:"is_chirpy_red"`
	}{
		ID:           user.ID,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Email:        user.Email,
		Token:        token,
		RefreshToken: refreshToken.Token,
		IsChirpyRed:  user.IsChirpyRed,
	}
	respondWithJSON(w, http.StatusOK, userInfo)
}

// generate new access token for current user
func (cfg *apiConfig) handlerRefresh(w http.ResponseWriter, r *http.Request) {
	// validate refresh token
	userID, err := validateRefreshToken(cfg, r)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error(), err)
		return
	}

	// generate new access token
	accessToken, err := auth.MakeJWT(userID, cfg.jwtSecret)
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
	if err := cfg.queries.RevokeRefreshToken(r.Context(), refreshToken); err != nil {
		respondWithError(w, http.StatusUnauthorized, "invalid or expired refresh token", err)
		return
	}

	// success
	w.WriteHeader(http.StatusNoContent)
}

// update user email & password
func (cfg *apiConfig) handlerUpdateUser(w http.ResponseWriter, r *http.Request) {
	// validate JWT
	user, err := validateAccessToken(cfg, r)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, err.Error(), err)
		return
	}

	// decode request body
	type UpdateRequest struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var updateRequest UpdateRequest
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&updateRequest); err != nil {
		log.Println(err)
		w.WriteHeader(500)
		return
	}

	if updateRequest.Email == "" || updateRequest.Password == "" {
		respondWithError(w, http.StatusBadRequest, "requires username and password", nil)
		return
	}

	// create new user parameters
	hashedPassword, err := auth.HashPassword(updateRequest.Password)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	params := database.UpdateUserInfoParams{
		ID:             user.ID,
		Email:          updateRequest.Email,
		HashedPassword: hashedPassword,
	}
	newUser, err := cfg.queries.UpdateUserInfo(r.Context(), params)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// respond with user information
	userInfo := struct {
		ID          uuid.UUID `json:"id"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		Email       string    `json:"email"`
		IsChirpyRed bool      `json:"is_chirpy_red"`
	}{
		ID:          newUser.ID,
		CreatedAt:   newUser.CreatedAt,
		UpdatedAt:   newUser.UpdatedAt,
		Email:       newUser.Email,
		IsChirpyRed: newUser.IsChirpyRed,
	}
	respondWithJSON(w, http.StatusOK, userInfo)
}

// check for a valid access token
// return user_id if valid
func validateAccessToken(cfg *apiConfig, r *http.Request) (database.User, error) {
	// get auth token from request header
	accessToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		log.Println(err)
		return database.User{}, errors.New("invalid or expired access token")
	}

	// validate access token
	userID, err := auth.ValidateJWT(accessToken, cfg.jwtSecret)
	if err != nil {
		log.Println(err)
		return database.User{}, errors.New("invalid or expired access token")
	}

	// get user from database
	user, err := cfg.queries.GetUserByID(r.Context(), userID)
	if err != nil {
		log.Println(err)
		return database.User{}, errors.New("invalid or expired access token")
	}

	//return user
	return user, nil
}

// check for a valid refresh token
// return user_id if valid
func validateRefreshToken(cfg *apiConfig, r *http.Request) (uuid.UUID, error) {
	// get refresh token from request header
	refreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		return uuid.Nil, errors.New("invalid or expired refresh token")
	}

	// get user ID for refresh token
	user, err := cfg.queries.GetUserFromRefreshToken(r.Context(), refreshToken)
	if err != nil {
		return uuid.Nil, err
	}

	// check expiration
	if user.ExpiresAt.Before(time.Now()) || user.RevokedAt.Valid {
		return uuid.Nil, errors.New("invalid or expired refresh token")
	}

	// return user ID
	return user.ID, nil
}
