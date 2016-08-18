package g2fa

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"time"
)

const (
	googleAuthenticatorKeySize = 10
	defaultTimeWindowSize      = 30
)

// GenerateKey generates random crypto key of requested length in bytes.
func GenerateKey() ([]byte, error) {
	key := make([]byte, googleAuthenticatorKeySize)
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
	key, err := base32.StdEncoding.DecodeString(strings.ToUpper(skey))
	if err != nil {
		return nil, err
	}
	if len(key) != googleAuthenticatorKeySize {
		return nil, errors.New("Key is not 80 bits")
	}
	return key, err
}

func timeVariable() int64 {
	return time.Now().Unix() / defaultTimeWindowSize
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

func generateHMAC(key []byte, variable int64) ([]byte, error) {
	list := bytes.Buffer{}
	err := binary.Write(&list, binary.BigEndian, variable)
	if err != nil {
		return nil, err
	}
	macProducer := hmac.New(sha1.New, key)
	macProducer.Write(list.Bytes())
	return macProducer.Sum(nil), nil
}
