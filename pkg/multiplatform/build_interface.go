/*
Copyright 2018 Google LLC

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

package multiplatform

import (
	"fmt"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/Gosayram/kaniko/pkg/config"
)

// BuildFunc is a function type that can build an image with given options
type BuildFunc func(*config.KanikoOptions) (v1.Image, error)

// DefaultBuildFunc is the default build function that will be set by the executor package
var DefaultBuildFunc BuildFunc

// SetBuildFunc sets the build function that should be used for building images
func SetBuildFunc(f BuildFunc) {
	DefaultBuildFunc = f
}

// BuildImage builds an image using the configured build function
func BuildImage(opts *config.KanikoOptions) (v1.Image, error) {
	if DefaultBuildFunc == nil {
		return nil, fmt.Errorf("no build function configured")
	}
	return DefaultBuildFunc(opts)
}
