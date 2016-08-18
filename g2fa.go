package g2fa

import (
	"crypto/rand"
	"encoding/base32"
	"io"
)

const (
	// GoogleAuthenticator is a key size compatible with Goole's authenticator app.
	GoogleAuthenticator = 10
)

// GenerateKey generates random crypto key of requested length in bytes.
func GenerateKey(size int) ([]byte, error) {
	key := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// EncodeKey converts a binary key to a user friendly base32 string.
func EncodeKey(key []byte) string {
	return base32.StdEncoding.EncodeToString(key)
}
