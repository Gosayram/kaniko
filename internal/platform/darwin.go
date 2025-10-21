//go:build darwin
// +build darwin

// Package platform provides platform-specific utilities for Darwin/macOS systems.
package platform

import "runtime"

// PossibleCPUs returns the set of possible CPUs on Darwin/macOS.
// On macOS, we use runtime.NumCPU() as the number of possible CPUs.
func PossibleCPUs() []int {
	ncpu := runtime.NumCPU()
	var cpus []int
	for i := 0; i < ncpu; i++ {
		cpus = append(cpus, i)
	}
	return cpus
}

// RuntimeArchitecture gets the name of the current architecture on Darwin
func RuntimeArchitecture() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64", nil
	case "arm64":
		return "arm64", nil
	case "386":
		return "i686", nil
	case "arm":
		return "arm", nil
	default:
		return runtime.GOARCH, nil
	}
}
