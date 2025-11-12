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

package logging

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestKanikoFormatter_Format(t *testing.T) {
	tests := []struct {
		name      string
		formatter *KanikoFormatter
		entry     *logrus.Entry
		want      string
	}{
		{
			name:      "Basic info log with timestamp and level",
			formatter: NewKanikoFormatter(),
			entry: &logrus.Entry{
				Level:   logrus.InfoLevel,
				Message: "Test message",
				Time:    time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			want: "INFO",
		},
		{
			name:      "Error log",
			formatter: NewKanikoFormatter(),
			entry: &logrus.Entry{
				Level:   logrus.ErrorLevel,
				Message: "Error occurred",
				Time:    time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			want: "ERROR",
		},
		{
			name:      "Warning log",
			formatter: NewKanikoFormatter(),
			entry: &logrus.Entry{
				Level:   logrus.WarnLevel,
				Message: "Warning message",
				Time:    time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			want: "WARN",
		},
		{
			name:      "Debug log",
			formatter: NewKanikoFormatter(),
			entry: &logrus.Entry{
				Level:   logrus.DebugLevel,
				Message: "Debug message",
				Time:    time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			want: "DEBUG",
		},
		{
			name:      "Log with fields",
			formatter: NewKanikoFormatter(),
			entry: &logrus.Entry{
				Level:   logrus.InfoLevel,
				Message: "Message with fields",
				Time:    time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
				Data: logrus.Fields{
					"key1": "value1",
					"key2": 42,
				},
			},
			want: "key1",
		},
		{
			name:      "Compact mode without timestamp",
			formatter: NewCompactKanikoFormatter(),
			entry: &logrus.Entry{
				Level:   logrus.InfoLevel,
				Message: "Compact message",
				Time:    time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			want: "INFO",
		},
		{
			name:      "Message cleanup - Using files from context",
			formatter: NewKanikoFormatter(),
			entry: &logrus.Entry{
				Level:   logrus.InfoLevel,
				Message: "Using files from context: [/path/to/file]",
				Time:    time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			want: "Context files",
		},
		{
			name:      "Message cleanup - Building stage",
			formatter: NewKanikoFormatter(),
			entry: &logrus.Entry{
				Level:   logrus.InfoLevel,
				Message: "Building stage test",
				Time:    time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
			},
			want: "Building",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.formatter.Format(tt.entry)
			if err != nil {
				t.Fatalf("Format() error = %v", err)
			}

			resultStr := string(result)
			if !strings.Contains(resultStr, tt.want) {
				t.Errorf("Format() result = %q, want to contain %q", resultStr, tt.want)
			}

			// Ensure result ends with newline
			if !strings.HasSuffix(resultStr, "\n") {
				t.Errorf("Format() result should end with newline, got %q", resultStr)
			}
		})
	}
}

func TestKanikoFormatter_GetLevelColor(t *testing.T) {
	formatter := NewKanikoFormatter()

	tests := []struct {
		level logrus.Level
		want  string
	}{
		{logrus.ErrorLevel, colorRed},
		{logrus.FatalLevel, colorRed},
		{logrus.PanicLevel, colorRed},
		{logrus.WarnLevel, colorYellow},
		{logrus.InfoLevel, colorBlue},
		{logrus.DebugLevel, colorGray},
		{logrus.TraceLevel, colorGray},
	}

	for _, tt := range tests {
		t.Run(tt.level.String(), func(t *testing.T) {
			got := formatter.getLevelColor(tt.level)
			if got != tt.want {
				t.Errorf("getLevelColor(%v) = %v, want %v", tt.level, got, tt.want)
			}
		})
	}
}

func TestKanikoFormatter_CleanupMessage(t *testing.T) {
	formatter := NewKanikoFormatter()

	tests := []struct {
		input string
		want  string
	}{
		{"Using files from context: []", "Context files: []"},
		{"Building stage test", "Building test"},
		{"Taking snapshot", "Snapshot"},
		{"No files changed", "No changes"},
		{"Skipping snapshotting", "Skipping"},
		{"Retrieving image", "Retrieving"},
		{"Returning cached", "Cached"},
		{"Unpacking rootfs", "Unpacking"},
		{"Creating directory", "Creating dir"},
		{"INFO[0000] Test message", "Test message"},
		{"WARN[0000] Warning", "Warning"},
		{"ERROR[0000] Error", "Error"},
		{"DEBUG[0000] Debug", "Debug"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := formatter.cleanupMessage(tt.input)
			if !strings.Contains(got, tt.want) {
				t.Errorf("cleanupMessage(%q) = %q, want to contain %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestKanikoFormatter_ShouldUseColors(t *testing.T) {
	tests := []struct {
		name      string
		setup     func()
		cleanup   func()
		formatter *KanikoFormatter
		want      bool
	}{
		{
			name: "ForceColors enabled",
			formatter: &KanikoFormatter{
				ForceColors: true,
			},
			want: true,
		},
		{
			name: "DisableColors enabled",
			formatter: &KanikoFormatter{
				DisableColors: true,
			},
			want: false,
		},
		{
			name: "NO_COLOR environment variable",
			setup: func() {
				os.Setenv("NO_COLOR", "1")
			},
			cleanup: func() {
				os.Unsetenv("NO_COLOR")
			},
			formatter: NewKanikoFormatter(),
			want:      false,
		},
		{
			name: "KANIKO_DISABLE_COLORS environment variable",
			setup: func() {
				os.Setenv("KANIKO_DISABLE_COLORS", "1")
			},
			cleanup: func() {
				os.Unsetenv("KANIKO_DISABLE_COLORS")
			},
			formatter: NewKanikoFormatter(),
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}
			if tt.cleanup != nil {
				defer tt.cleanup()
			}

			got := tt.formatter.shouldUseColors()
			if got != tt.want {
				t.Errorf("shouldUseColors() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewKanikoFormatter(t *testing.T) {
	formatter := NewKanikoFormatter()

	if formatter == nil {
		t.Fatal("NewKanikoFormatter() returned nil")
	}

	if !formatter.ShowTimestamp {
		t.Error("NewKanikoFormatter() ShowTimestamp should be true")
	}
	if !formatter.ShowLevel {
		t.Error("NewKanikoFormatter() ShowLevel should be true")
	}
	if formatter.CompactMode {
		t.Error("NewKanikoFormatter() CompactMode should be false")
	}
}

func TestNewCompactKanikoFormatter(t *testing.T) {
	formatter := NewCompactKanikoFormatter()

	if formatter == nil {
		t.Fatal("NewCompactKanikoFormatter() returned nil")
	}

	if formatter.ShowTimestamp {
		t.Error("NewCompactKanikoFormatter() ShowTimestamp should be false")
	}
	if !formatter.ShowLevel {
		t.Error("NewCompactKanikoFormatter() ShowLevel should be true")
	}
	if !formatter.CompactMode {
		t.Error("NewCompactKanikoFormatter() CompactMode should be true")
	}
}

func TestConfigureKanikoLogging(t *testing.T) {
	tests := []struct {
		name        string
		level       string
		format      string
		timestamp   bool
		wantErr     bool
		errContains string
	}{
		{
			name:   "Valid kaniko format",
			level:  "info",
			format: "kaniko",
		},
		{
			name:   "Valid kaniko-compact format",
			level:  "debug",
			format: "kaniko-compact",
		},
		{
			name:   "Valid json format",
			level:  "warn",
			format: "json",
		},
		{
			name:   "Valid text format",
			level:  "error",
			format: "text",
		},
		{
			name:   "Valid color format",
			level:  "info",
			format: "color",
		},
		{
			name:        "Invalid format",
			level:       "info",
			format:      "invalid",
			wantErr:     true,
			errContains: "unsupported log format",
		},
		{
			name:        "Invalid level",
			level:       "invalid",
			format:      "kaniko",
			wantErr:     true,
			errContains: "parsing log level",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ConfigureKanikoLogging(tt.level, tt.format, tt.timestamp)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConfigureKanikoLogging() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil {
				if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("ConfigureKanikoLogging() error = %v, want to contain %q", err, tt.errContains)
				}
			}
		})
	}
}
