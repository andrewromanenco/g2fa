package g2fa

import (
	"reflect"
	"testing"
)

func TestGenerateKeyReturnsDifferentKeyOnEachCall(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()
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

func TestDecodeKeyCorrectlyDecodesBase32String(t *testing.T) {
	skey := "4ZY6BAWHCGSMKBWY"
	key := []byte{0xe6, 0x71, 0xe0, 0x82, 0xc7, 0x11, 0xa4, 0xc5, 0x06, 0xd8}
	decoded, _ := DecodeKey(skey)
	if !reflect.DeepEqual(key, decoded) {
		t.Error("Key was not decoded correctly")
	}
}

func TestDecodeKeyIgnoresCase(t *testing.T) {
	skey := "4zy6bawhcgsmkbwy"
	key := []byte{0xe6, 0x71, 0xe0, 0x82, 0xc7, 0x11, 0xa4, 0xc5, 0x06, 0xd8}
	decoded, _ := DecodeKey(skey)
	if !reflect.DeepEqual(key, decoded) {
		t.Error("Key was not decoded correctly")
	}
}

func TestEncodeKeyFailsOnWrongKeyLength(t *testing.T) {
	skey := "GEZDG==="
	_, err := DecodeKey(skey)
	if err == nil {
		t.Error("Must fail for key has wrong length")
	}
}

func TestDecodeKeyFailsIfInputIsNotCorrect(t *testing.T) {
	skey := "#$j\njj$"
	_, err := DecodeKey(skey)
	if err == nil {
		t.Error("Must fail if input is not write encoding")
	}
}

// testDecodeHMAC uses test data from RFC4226/5.4
func testDecodeHMAC(t *testing.T) {
	hmac := []byte{0x1f, 0x86, 0x98, 0x69, 0x0e, 0x02, 0xca, 0x16, 0x61, 0x85, 0x50, 0xef, 0x7f, 0x19, 0xda, 0x8e, 0x94, 0x5b, 0x55, 0x5a}
	code := decodeHMAC(hmac)
	if code != 872921 {
		t.Error("Returned code does not match expectation")
	}
}

func testGenerateHMAC(t *testing.T) {
	key := []byte{0xe6, 0x71, 0xe0, 0x82, 0xc7, 0x11, 0xa4, 0xc5, 0x06, 0xd8}
	hmac, _ := generateHMAC(key, 49051776)
	if !reflect.DeepEqual(hmac, []byte{0xc9, 0x0e, 0xed, 0xbd, 0xc7, 0x2d, 0x13, 0xd9, 0xd7, 0x51, 0x76, 0xb6, 0xef, 0x6e, 0x2a, 0xe5, 0x99, 0x14, 0x98, 0x62}) {
		t.Error("HMAC result is not as expected")
	}
}
