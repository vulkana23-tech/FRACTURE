package attrmgr

import (
	"testing"
)

func FuzzGetAttributesFromIdemix(f *testing.F) {
	f.Add([]byte{0x08, 0x01, 0x12, 0x03, 0x61, 0x62, 0x63}) // Valid serialized identity
	f.Add([]byte{}) // Empty input
	f.Add([]byte{0x00, 0x00, 0x00}) // Invalid protobuf

	f.Fuzz(func(t *testing.T, data []byte) {
		mgr := &Mgr{}
		_, err := mgr.GetAttributesFromIdemix(data)
		if err != nil {
			// Expected errors for invalid inputs
			return
		}
	})
}