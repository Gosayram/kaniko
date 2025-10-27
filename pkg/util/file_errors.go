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

package util

import (
	"github.com/sirupsen/logrus"
)

// Common error handling patterns
// These functions provide common error handling patterns used across file operations

// CommonErrorHandler provides common error handling for file operations
type CommonErrorHandler struct {
	LogErrors       bool
	ContinueOnError bool
}

// DefaultErrorHandler returns default error handling configuration
func DefaultErrorHandler() CommonErrorHandler {
	return CommonErrorHandler{
		LogErrors:       true,
		ContinueOnError: false,
	}
}

// HandleFileOperationError handles errors from file operations with common patterns
func HandleFileOperationError(err error, handler CommonErrorHandler, operation string, path string) error {
	if err == nil {
		return nil
	}

	if handler.LogErrors {
		logrus.Errorf("Error during %s for path %s: %v", operation, path, err)
	}

	if handler.ContinueOnError {
		return nil // Continue processing other files
	}

	return err
}
