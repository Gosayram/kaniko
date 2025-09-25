/*
Copyright 2025 Google LLC

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

// Package debug provides debugging and logging utilities for Kaniko.
package debug

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/config"
)

// Manager manages debugging and logging functionality for Kaniko.
type Manager struct {
	opts          *config.DebugOptions
	logFile       *os.File
	componentLogs map[string]*logrus.Logger
}

var (
	defaultManager *Manager
)

// Init initializes a new DebugManager with the provided options.
func Init(opts *config.DebugOptions) (*Manager, error) {
	dm := &Manager{
		opts:          opts,
		componentLogs: make(map[string]*logrus.Logger),
	}

	if opts.OutputDebugFiles {
		if err := dm.initDebugFiles(); err != nil {
			return nil, err
		}
	}

	defaultManager = dm
	return dm, nil
}

func (dm *Manager) initDebugFiles() error {
	debugDir := filepath.Join(config.KanikoDir, "debug")
	const dirPermissions = 0o750
	if err := os.MkdirAll(debugDir, dirPermissions); err != nil {
		return err
	}

	timestamp := time.Now().Format("20060102-150405")

	// Create main debug log file
	logFileName := "kaniko-debug-" + timestamp + ".log"
	// Validate log file name to prevent path traversal
	if strings.Contains(logFileName, "..") || strings.Contains(logFileName, "/") {
		return fmt.Errorf("invalid log file name: %s", logFileName)
	}
	file, err := os.Create(filepath.Join(debugDir, logFileName))
	if err != nil {
		return err
	}
	dm.logFile = file

	// Create organized subdirectories for different log types
	subDirs := []string{
		"build-steps",
		"multi-platform",
		"oci-operations",
		"filesystem",
		"registry",
		"cache",
	}

	for _, subDir := range subDirs {
		fullPath := filepath.Join(debugDir, subDir)
		if err := os.MkdirAll(fullPath, dirPermissions); err != nil {
			return err
		}
	}

	return nil
}

// LogComponent logs a message for a specific component.
func (dm *Manager) LogComponent(component, msg string, args ...interface{}) {
	if !dm.shouldLogComponent(component) {
		return
	}

	formattedMsg := fmt.Sprintf(msg, args...)
	logEntry := fmt.Sprintf("[%s] [%s] %s", time.Now().Format(time.RFC3339), component, formattedMsg)

	if dm.logFile != nil {
		if _, err := fmt.Fprintln(dm.logFile, logEntry); err != nil {
			logrus.Errorf("Failed to write to debug log: %v", err)
		}
	}

	logrus.Debugf("[%s] %s", component, formattedMsg)
}

func (dm *Manager) shouldLogComponent(component string) bool {
	if dm.opts.EnableFullDebug {
		return true
	}

	if len(dm.opts.DebugComponents) == 0 {
		return false
	}

	for _, comp := range dm.opts.DebugComponents {
		if comp == component {
			return true
		}
	}

	return false
}

// Close closes the debug manager and releases any resources.
func (dm *Manager) Close() error {
	if dm.logFile != nil {
		return dm.logFile.Close()
	}
	return nil
}

// LogToComponentFile writes logs to component-specific files
func (dm *Manager) LogToComponentFile(component, msg string, args ...interface{}) error {
	if !dm.opts.OutputDebugFiles {
		return nil
	}

	if !dm.shouldLogComponent(component) {
		return nil
	}

	formattedMsg := fmt.Sprintf(msg, args...)
	timestamp := time.Now().Format(time.RFC3339)
	logEntry := fmt.Sprintf("[%s] %s", timestamp, formattedMsg)

	// Determine the appropriate subdirectory based on component
	var subDir string
	switch {
	case strings.Contains(component, "build"):
		subDir = "build-steps"
	case strings.Contains(component, "multiplatform") || strings.Contains(component, "driver"):
		subDir = "multi-platform"
	case strings.Contains(component, "oci"):
		subDir = "oci-operations"
	case strings.Contains(component, "filesystem") || strings.Contains(component, "snapshot"):
		subDir = "filesystem"
	case strings.Contains(component, "registry"):
		subDir = "registry"
	case strings.Contains(component, "cache"):
		subDir = "cache"
	default:
		subDir = "other"
	}

	debugDir := filepath.Join(config.KanikoDir, "debug", subDir)
	filename := fmt.Sprintf("%s.log", component)

	filePath := filepath.Join(debugDir, filename)
	const filePermissions = 0o600
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, filePermissions)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.WriteString(logEntry + "\n"); err != nil {
		return err
	}

	return nil
}

// GetDebugDir returns the path to the debug directory
func (dm *Manager) GetDebugDir() string {
	return filepath.Join(config.KanikoDir, "debug")
}

// LogComponent logs a message for a specific component.
func LogComponent(component, msg string, args ...interface{}) {
	if defaultManager != nil {
		defaultManager.LogComponent(component, msg, args...)
	}
}

// LogToComponentFile writes logs to component-specific files.
func LogToComponentFile(component, msg string, args ...interface{}) error {
	if defaultManager != nil {
		return defaultManager.LogToComponentFile(component, msg, args...)
	}
	return nil
}

// ShouldLogComponent determines if a component should be logged based on current settings.
func ShouldLogComponent(component string) bool {
	if defaultManager != nil {
		return defaultManager.shouldLogComponent(component)
	}
	return false
}

// Close closes the default debug manager and releases any resources.
func Close() error {
	if defaultManager != nil {
		return defaultManager.Close()
	}
	return nil
}
