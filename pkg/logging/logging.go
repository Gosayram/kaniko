/*
Copyright 2020 Google LLC

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

// Package logging provides configuration utilities for logrus logging
// including log levels, formats, and timestamp settings
package logging

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	// DefaultLevel is the default log level used when no level is specified
	DefaultLevel = "info"
	// DefaultLogTimestamp controls whether timestamps are shown in logs by default
	DefaultLogTimestamp = false

	// FormatText represents plain text log format without colors
	FormatText = "text"
	// FormatColor represents colored text log format with ANSI colors
	FormatColor = "color"
	// FormatJSON represents JSON log format for structured logging
	FormatJSON = "json"
)

// Configure sets the logrus logging level and formatter
func Configure(level, format string, logTimestamp bool) error {
	// Use enhanced Kaniko logging if supported format is requested
	if format == "kaniko" || format == "kaniko-compact" {
		return ConfigureKanikoLogging(level, format, logTimestamp)
	}

	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		return errors.Wrap(err, "parsing log level")
	}
	logrus.SetLevel(lvl)

	var formatter logrus.Formatter
	switch format {
	case FormatText:
		formatter = &logrus.TextFormatter{
			DisableColors: true,
			FullTimestamp: logTimestamp,
		}
	case FormatColor:
		formatter = &logrus.TextFormatter{
			ForceColors:   true,
			FullTimestamp: logTimestamp,
		}
	case FormatJSON:
		formatter = &logrus.JSONFormatter{}
	default:
		return fmt.Errorf("not a valid log format: %q. Please specify one of (text, color, json, kaniko, kaniko-compact)",
			format)
	}
	logrus.SetFormatter(formatter)

	return nil
}
