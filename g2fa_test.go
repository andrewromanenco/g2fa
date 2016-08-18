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
