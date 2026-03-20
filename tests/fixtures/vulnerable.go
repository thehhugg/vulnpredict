package main

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"unsafe"
)

// VP-GO-001: SQL injection via string concatenation
func getUserByName(db *sql.DB, name string) {
	query := "SELECT * FROM users WHERE name = '" + name + "'"
	db.Query(query)
}

// VP-GO-001: SQL injection via fmt.Sprintf
func getUserByID(db *sql.DB, id string) {
	query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", id)
	db.Query(query)
}

// VP-GO-002: Command injection
func runCommand(input string) {
	exec.Command(input)
}

// VP-GO-003: Shell command execution
func runShell(cmd string) {
	exec.Command("bash", "-c", cmd)
}

// VP-GO-004: Path traversal
func serveFile(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join("/data", r.URL.Path)
	http.ServeFile(w, r, path)
}

// VP-GO-005: Weak crypto - DES
func weakDES() {
	block, _ := des.NewCipher([]byte("12345678"))
	_ = block
}

// VP-GO-006: Weak crypto - RC4
func weakRC4() {
	cipher, _ := rc4.NewCipher([]byte("key"))
	_ = cipher
}

// VP-GO-007: MD5 for hashing
func hashMD5(data []byte) {
	h := md5.New()
	h.Write(data)
}

// VP-GO-008: SHA1 for hashing
func hashSHA1(data []byte) {
	h := sha1.New()
	h.Write(data)
}

// VP-GO-009: Hardcoded password
var password = "SuperSecretPassword123!"

// VP-GO-010: Insecure TLS
func insecureTLS() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	return &http.Client{Transport: tr}
}

// VP-GO-013: Unsafe pointer
func unsafeOp() {
	var x int = 42
	p := unsafe.Pointer(&x)
	_ = p
}

// VP-GO-014: Ignored error
func ignoredError() {
	resp, _ := http.Get("https://example.com")
	_ = resp
}

// VP-GO-015: HTTP without timeout
func defaultHTTP() {
	http.Get("https://example.com")
}
