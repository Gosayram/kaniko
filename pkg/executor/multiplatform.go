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

package executor

import (
	"context"

	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/multiplatform"
	"github.com/Gosayram/kaniko/pkg/oci"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// DoMultiPlatformBuild executes multi-platform builds using the specified driver
func DoMultiPlatformBuild(opts *config.KanikoOptions) (v1.ImageIndex, error) {
	logrus.Info("Starting multi-platform build")

	// Create coordinator for multi-platform builds
	coordinator, err := multiplatform.NewCoordinator(opts)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create multi-platform coordinator")
	}

	// Execute multi-platform builds
	index, err := coordinator.Execute(context.Background())
	if err != nil {
		return nil, errors.Wrap(err, "failed to execute multi-platform builds")
	}

	// Push the image index if requested
	if opts.PublishIndex && index != nil {
		if err := oci.PushIndex(index, opts); err != nil {
			return nil, errors.Wrap(err, "failed to push image index")
		}
	}

	return index, nil
}
