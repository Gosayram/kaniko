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

type DebugManager struct {
	opts          *config.DebugOptions
	logFile       *os.File
	componentLogs map[string]*logrus.Logger
}

var (
	defaultManager *DebugManager
)

func Init(opts *config.DebugOptions) (*DebugManager, error) {
	dm := &DebugManager{
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

func (dm *DebugManager) initDebugFiles() error {
	debugDir := filepath.Join(config.KanikoDir, "debug")
	if err := os.MkdirAll(debugDir, 0755); err != nil {
		return err
	}

	timestamp := time.Now().Format("20060102-150405")

	// Create main debug log file
	logFile := filepath.Join(debugDir, "kaniko-debug-"+timestamp+".log")
	file, err := os.Create(logFile)
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
		if err := os.MkdirAll(fullPath, 0755); err != nil {
			return err
		}
	}

	return nil
}

func (dm *DebugManager) LogComponent(component string, msg string, args ...interface{}) {
	if !dm.shouldLogComponent(component) {
		return
	}

	formattedMsg := fmt.Sprintf(msg, args...)
	logEntry := fmt.Sprintf("[%s] [%s] %s", time.Now().Format(time.RFC3339), component, formattedMsg)

	if dm.logFile != nil {
		fmt.Fprintln(dm.logFile, logEntry)
	}

	logrus.Debugf("[%s] %s", component, formattedMsg)
}

func (dm *DebugManager) shouldLogComponent(component string) bool {
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

func (dm *DebugManager) Close() error {
	if dm.logFile != nil {
		return dm.logFile.Close()
	}
	return nil
}

// LogToComponentFile writes logs to component-specific files
func (dm *DebugManager) LogToComponentFile(component string, msg string, args ...interface{}) error {
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
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
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
func (dm *DebugManager) GetDebugDir() string {
	return filepath.Join(config.KanikoDir, "debug")
}

// Global functions for convenience
func LogComponent(component string, msg string, args ...interface{}) {
	if defaultManager != nil {
		defaultManager.LogComponent(component, msg, args...)
	}
}

func LogToComponentFile(component string, msg string, args ...interface{}) error {
	if defaultManager != nil {
		return defaultManager.LogToComponentFile(component, msg, args...)
	}
	return nil
}

func ShouldLogComponent(component string) bool {
	if defaultManager != nil {
		return defaultManager.shouldLogComponent(component)
	}
	return false
}

func Close() error {
	if defaultManager != nil {
		return defaultManager.Close()
	}
	return nil
}
