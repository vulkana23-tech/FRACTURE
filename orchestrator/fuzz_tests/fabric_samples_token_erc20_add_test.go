package chaincode

import (
	"testing"
)

func FuzzAdd(f *testing.F) {
	f.Add(int(1), int(2)) // seed
	f.Fuzz(func(t *testing.T, b int, q int) {
		_, err := add(b, q)
		if err != nil {
			return
		}
	})
}