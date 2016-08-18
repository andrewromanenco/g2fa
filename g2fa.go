package g2fa

import (
	"crypto/rand"
	"encoding/base32"
	"io"
	"strings"
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

// DecodeKey converts a base32 key to a binary representation.
func DecodeKey(skey string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(strings.ToUpper(skey))
}

// decodeHMAC extracts code from a HMAC according to RFC4226
func decodeHMAC(hash []byte) int32 {
	if len(hash) != 20 {
		panic("Not a HMAC-SHA1 value")
	}
	offset := hash[19] & 0xf
	binCode := int32(0)
	binCode += int32(hash[offset+3])
	binCode += (int32(hash[offset+2]) << 8)
	binCode += (int32(hash[offset+1]) << 16)
	binCode += (int32(hash[offset]&0x7f) << 24)
	return binCode % 1000000
}
