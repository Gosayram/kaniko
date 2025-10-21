//go:build !linux && !windows && !darwin

package platform

import (
	"runtime"
)

// possibleCPUs returns the set of possible CPUs on Unix systems.
// This is a fallback implementation for systems that don't have
// Linux-specific CPU detection capabilities.
func possibleCPUs() []int {
	// For non-Linux Unix systems, we use runtime.NumCPU() as a fallback
	ncpu := runtime.NumCPU()

	// Create a simple range from 0 to NumCPU()-1
	var cpus []int
	for i := 0; i < ncpu; i++ {
		cpus = append(cpus, i)
	}

	return cpus
}
