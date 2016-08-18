package g2fa

import (
	"crypto/rand"
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
