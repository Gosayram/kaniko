//go:build darwin
// +build darwin

package platform

import "runtime"

// possibleCPUs returns the set of possible CPUs on Darwin/macOS.
// On macOS, we use runtime.NumCPU() as the number of possible CPUs.
func possibleCPUs() []int {
	ncpu := runtime.NumCPU()
	var cpus []int
	for i := 0; i < ncpu; i++ {
		cpus = append(cpus, i)
	}
	return cpus
}

// runtimeArchitecture gets the name of the current architecture on Darwin
func runtimeArchitecture() (string, error) {
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