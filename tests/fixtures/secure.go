package main

import (
	"crypto/aes"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"net/http"
	"os"
	"time"
)

// Safe: parameterized query
func getUserSafe(db *sql.DB, name string) (*sql.Row, error) {
	return db.QueryRow("SELECT * FROM users WHERE name = ?", name), nil
}

// Safe: proper TLS configuration
func secureTLS() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	return &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}
}

// Safe: proper error handling
func readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Safe: strong crypto
func strongCrypto() {
	block, _ := aes.NewCipher([]byte("0123456789abcdef"))
	_ = block
	h := sha256.New()
	h.Write([]byte("data"))
}

// Safe: password from environment
func getPassword() string {
	return os.Getenv("DB_PASSWORD")
}
