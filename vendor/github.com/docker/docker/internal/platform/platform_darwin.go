//go:build darwin

package platform

import (
	"runtime"
)

// possibleCPUs returns the set of possible CPUs on macOS.
// On macOS, we use runtime.NumCPU() as a fallback since there's no direct
// equivalent to Linux's /sys/devices/system/cpu/possible.
func possibleCPUs() []int {
	// On macOS, we can't easily determine the actual possible CPUs
	// like on Linux, so we fall back to runtime.NumCPU()
	ncpu := runtime.NumCPU()

	// Create a simple range from 0 to NumCPU()-1
	var cpus []int
	for i := 0; i < ncpu; i++ {
		cpus = append(cpus, i)
	}

	return cpus
}
