/*
Copyright 2024 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package network

import (
	"context"
	"runtime"
	"testing"
	"time"
)

// TestRegistryClient_TimeoutWarningGoroutineLeak tests that
// timeout warning goroutines properly terminate
func TestRegistryClient_TimeoutWarningGoroutineLeak(t *testing.T) {
	// Wait for any background goroutines from previous tests to settle
	time.Sleep(500 * time.Millisecond)
	runtime.GC()

	beforeGoroutines := runtime.NumGoroutine()

	// Simulate the timeout warning pattern from PullImage/PushImage
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	warningThreshold := 4 * time.Second // 80% of 5 seconds
	warningCtx, warningCancel := context.WithCancel(ctx)
	done := make(chan bool, 1)

	go func() {
		defer warningCancel() // Ensure cleanup
		select {
		case <-time.After(warningThreshold):
			select {
			case <-warningCtx.Done():
				// Operation completed or canceled
			default:
				// Would log warning here
			}
		case <-warningCtx.Done():
			// Operation completed or canceled
		}
		done <- true
	}()

	// Cancel context before timeout (simulating fast operation)
	time.Sleep(100 * time.Millisecond)
	cancel()

	// Wait for goroutine to finish
	select {
	case <-done:
		// Goroutine properly terminated
	case <-time.After(1 * time.Second):
		t.Error("Timeout warning goroutine did not terminate")
	}

	// Wait for cleanup
	time.Sleep(500 * time.Millisecond)
	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	runtime.GC()

	afterGoroutines := runtime.NumGoroutine()

	// Allow some margin for background goroutines
	if afterGoroutines > beforeGoroutines+5 {
		t.Errorf("Possible goroutine leak in timeout warning: before=%d, after=%d (increase: %d)",
			beforeGoroutines, afterGoroutines, afterGoroutines-beforeGoroutines)
	} else {
		t.Logf("Goroutine count: before=%d, after=%d (increase: %d)",
			beforeGoroutines, afterGoroutines, afterGoroutines-beforeGoroutines)
	}
}

// TestRegistryClient_TimeoutWarningGoroutineLeak_Timeout tests that
// timeout warning goroutines properly terminate even when timeout occurs
func TestRegistryClient_TimeoutWarningGoroutineLeak_Timeout(t *testing.T) {
	// Wait for any background goroutines from previous tests to settle
	time.Sleep(500 * time.Millisecond)
	runtime.GC()

	beforeGoroutines := runtime.NumGoroutine()

	// Simulate the timeout warning pattern with actual timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	warningThreshold := 800 * time.Millisecond // 80% of 1 second
	warningCtx, warningCancel := context.WithCancel(ctx)
	done := make(chan bool, 1)

	go func() {
		defer warningCancel() // Ensure cleanup
		select {
		case <-time.After(warningThreshold):
			select {
			case <-warningCtx.Done():
				// Operation completed or canceled
			default:
				// Would log warning here
			}
		case <-warningCtx.Done():
			// Operation completed or canceled
		}
		done <- true
	}()

	// Wait for timeout to occur
	time.Sleep(1200 * time.Millisecond)

	// Wait for goroutine to finish
	select {
	case <-done:
		// Goroutine properly terminated
	case <-time.After(500 * time.Millisecond):
		t.Error("Timeout warning goroutine did not terminate after timeout")
	}

	// Wait for cleanup
	time.Sleep(500 * time.Millisecond)
	runtime.GC()
	time.Sleep(200 * time.Millisecond)
	runtime.GC()

	afterGoroutines := runtime.NumGoroutine()

	// Allow some margin for background goroutines
	if afterGoroutines > beforeGoroutines+5 {
		t.Errorf("Possible goroutine leak in timeout warning (timeout case): before=%d, after=%d (increase: %d)",
			beforeGoroutines, afterGoroutines, afterGoroutines-beforeGoroutines)
	} else {
		t.Logf("Goroutine count: before=%d, after=%d (increase: %d)",
			beforeGoroutines, afterGoroutines, afterGoroutines-beforeGoroutines)
	}
}
