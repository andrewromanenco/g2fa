package g2fa

import (
	"reflect"
	"testing"
)

func TestGenerateKeyReturnsRequestedLength(t *testing.T) {
	key, _ := GenerateKey(5)
	if len(key) != 5 {
		t.Error("Must return requested key size")
	}
}

func TestGenerateKeyReturnsDifferentKeyOnEachCall(t *testing.T) {
	key1, _ := GenerateKey(5)
	key2, _ := GenerateKey(5)
	if reflect.DeepEqual(key1, key2) {
		t.Error("Key must be unique for every call")
	}
}

func TestEncodeKeyReturnsBase32String(t *testing.T) {
	key := []byte{0xe6, 0x71, 0xe0, 0x82, 0xc7, 0x11, 0xa4, 0xc5, 0x06, 0xd8}
	if EncodeKey(key) != "4ZY6BAWHCGSMKBWY" {
		t.Error("Key was not encoded correctly")
	}
}
