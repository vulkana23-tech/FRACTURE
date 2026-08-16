package chaincode

import (
	"testing"
)

func FuzzSub(f *testing.F) {
	f.Add(int(0), int(0))
	f.Add(int(100), int(50))
	f.Add(int(-100), int(50))
	f.Add(int(100), int(-50))
	f.Add(int(2147483647), int(1))
	f.Add(int(-2147483648), int(-1))

	f.Fuzz(func(t *testing.T, b int, q int) {
		_, err := sub(b, q)
		if err != nil {
			return
		}
	})
}