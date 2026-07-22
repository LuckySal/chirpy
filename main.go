package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"sync/atomic"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/luckysal/chirpy/internal/database"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	queries        *database.Queries
	platform       string
	jwtSecret      string
	polkaKey       string
}

func main() {
	// constants
	const port = "8080"
	const filepathRoot = "."

	// load environment
	godotenv.Load()
	env_ok := true
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		log.Println("DB_URL environment variable is not set")
		env_ok = false
	}
	platform := os.Getenv("PLATFORM")
	if platform == "" {
		log.Println("PLATFORM environment variable is not set")
		env_ok = false
	}
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Println("JWT_SECRET environment variable is not set")
		env_ok = false
	}
	polkaKey := os.Getenv("POLKA_KEY")
	if polkaKey == "" {
		log.Println("POLKA_KEY environment variable is not set")
		env_ok = false
	}
	if !env_ok {
		os.Exit(1)
	}

	// connect to database
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("Error connecting to database: ", err)
	}
	dbQueries := database.New(db)

	// create config struct
	cfg := apiConfig{fileserverHits: atomic.Int32{}, queries: dbQueries, platform: platform, jwtSecret: jwtSecret, polkaKey: polkaKey}

	// register endpoints
	mux := http.NewServeMux()
	mux.Handle("/app/", cfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(filepathRoot)))))

	mux.HandleFunc("GET /api/healthz", handlerReadiness)

	mux.HandleFunc("POST /api/users", cfg.handlerCreateUser)
	mux.HandleFunc("POST /api/login", cfg.handlerLogin)
	mux.HandleFunc("POST /api/refresh", cfg.handlerRefresh)
	mux.HandleFunc("POST /api/revoke", cfg.handlerRevoke)
	mux.HandleFunc("PUT /api/users", cfg.handlerUpdateUser)

	mux.HandleFunc("GET /api/chirps", cfg.handlerGetChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", cfg.handlerGetChirpByID)
	mux.HandleFunc("POST /api/chirps", cfg.handlerPostChirp)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", cfg.handlerDeleteChirp)

	mux.HandleFunc("POST /api/polka/webhooks", cfg.handlerWebhooks)

	mux.HandleFunc("POST /admin/reset", cfg.handlerReset)
	mux.HandleFunc("GET /admin/metrics", cfg.handlerMetrics)

	// create server struct
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	// start server
	log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
	log.Fatal(srv.ListenAndServe())
}
