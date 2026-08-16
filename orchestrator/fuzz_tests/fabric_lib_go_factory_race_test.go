package factory

import (
	"sync"
	"testing"
)

func TestRaceConditions(t *testing.T) {
	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			// Concurrent calls to InitFactories with different configs
			config := GetDefaultOpts()
			InitFactories(config)
			// Concurrent calls to GetDefault
			GetDefault()
		}()
	}

	wg.Wait()
}