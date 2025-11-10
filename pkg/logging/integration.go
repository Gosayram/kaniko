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
	"context"
	"time"

	"github.com/sirupsen/logrus"
)

// IntegrationManager manages structured logging integration across Kaniko components
type IntegrationManager struct {
	structuredLogger *StructuredLogger
	enhancedLogger   *EnhancedLogger
	context          context.Context
	enabled          bool
}

// NewIntegrationManager creates a new integration manager
func NewIntegrationManager() *IntegrationManager {
	return &IntegrationManager{
		structuredLogger: NewStructuredLogger(true, true, true, "info", "json"),
		enhancedLogger:   GetEnhancedLogger(),
		context:          context.Background(),
		enabled:          true,
	}
}

// EnableStructuredLogging enables structured logging for Kaniko components
func (im *IntegrationManager) EnableStructuredLogging() {
	im.enabled = true
	logrus.Info("Structured logging enabled for Kaniko components")
}

// DisableStructuredLogging disables structured logging
func (im *IntegrationManager) DisableStructuredLogging() {
	im.enabled = false
	logrus.Info("Structured logging disabled")
}

// LogBuildStart logs the start of a build process
func (im *IntegrationManager) LogBuildStart(buildID, dockerfilePath string, stages int) {
	if !im.enabled {
		logrus.Infof("Starting build %s with %d stages", buildID, stages)
		return
	}

	im.structuredLogger.Info("Build started", map[string]interface{}{
		"build_id":   buildID,
		"dockerfile": dockerfilePath,
		"stages":     stages,
		"timestamp":  time.Now().Unix(),
	})

	im.enhancedLogger.StartGroup("build-" + buildID)
}

// LogBuildComplete logs the completion of a build process
func (im *IntegrationManager) LogBuildComplete(buildID string, duration time.Duration, success bool) {
	if !im.enabled {
		status := StatusCompleted
		if !success {
			status = StatusFailed
		}
		logrus.Infof("Build %s %s in %v", buildID, status, duration)
		return
	}

	level := LevelInfo
	if !success {
		level = LevelError
	}

	if level == LevelError {
		im.structuredLogger.Error("Build completed", map[string]interface{}{
			"build_id":    buildID,
			"duration_ms": duration.Milliseconds(),
			"success":     success,
			"timestamp":   time.Now().Unix(),
		})
	} else {
		im.structuredLogger.Info("Build completed", map[string]interface{}{
			"build_id":    buildID,
			"duration_ms": duration.Milliseconds(),
			"success":     success,
			"timestamp":   time.Now().Unix(),
		})
	}

	im.enhancedLogger.EndGroup("build-" + buildID)
}

// LogStageStart logs the start of a build stage
func (im *IntegrationManager) LogStageStart(stageIndex int, stageName, baseImage string) {
	if !im.enabled {
		logrus.Infof("Building stage %d: %s (base: %s)", stageIndex, stageName, baseImage)
		return
	}

	im.structuredLogger.Info("Stage started", map[string]interface{}{
		"stage_index": stageIndex,
		"stage_name":  stageName,
		"base_image":  baseImage,
		"timestamp":   time.Now().Unix(),
	})

	im.enhancedLogger.StartGroup("stage-" + stageName)
}

// LogStageComplete logs the completion of a build stage
func (im *IntegrationManager) LogStageComplete(stageIndex int, stageName string, duration time.Duration, success bool) {
	if !im.enabled {
		status := StatusCompleted
		if !success {
			status = StatusFailed
		}
		logrus.Infof("Stage %d (%s) %s in %v", stageIndex, stageName, status, duration)
		return
	}

	level := LevelInfo
	if !success {
		level = LevelError
	}

	if level == LevelError {
		im.structuredLogger.Error("Stage completed", map[string]interface{}{
			"stage_index": stageIndex,
			"stage_name":  stageName,
			"duration_ms": duration.Milliseconds(),
			"success":     success,
			"timestamp":   time.Now().Unix(),
		})
	} else {
		im.structuredLogger.Info("Stage completed", map[string]interface{}{
			"stage_index": stageIndex,
			"stage_name":  stageName,
			"duration_ms": duration.Milliseconds(),
			"success":     success,
			"timestamp":   time.Now().Unix(),
		})
	}

	im.enhancedLogger.EndGroup("stage-" + stageName)
}

// LogCommandStart logs the start of a Docker command execution
func (im *IntegrationManager) LogCommandStart(commandIndex int, command, stageName string) {
	if !im.enabled {
		logrus.Infof("Executing command %d: %s", commandIndex, command)
		return
	}

	im.structuredLogger.Info("Command started", map[string]interface{}{
		"command_index": commandIndex,
		"command":       command,
		"stage":         stageName,
		"timestamp":     time.Now().Unix(),
	})
}

// LogCommandComplete logs the completion of a Docker command execution
func (im *IntegrationManager) LogCommandComplete(
	commandIndex int, command string, duration time.Duration, success bool) {
	if !im.enabled {
		status := StatusCompleted
		if !success {
			status = StatusFailed
		}
		logrus.Infof("Command %d %s in %v", commandIndex, status, duration)
		return
	}

	level := LevelInfo
	if !success {
		level = LevelError
	}

	if level == LevelError {
		im.structuredLogger.Error("Command completed", map[string]interface{}{
			"command_index": commandIndex,
			"command":       command,
			"duration_ms":   duration.Milliseconds(),
			"success":       success,
			"timestamp":     time.Now().Unix(),
		})
	} else {
		im.structuredLogger.Info("Command completed", map[string]interface{}{
			"command_index": commandIndex,
			"command":       command,
			"duration_ms":   duration.Milliseconds(),
			"success":       success,
			"timestamp":     time.Now().Unix(),
		})
	}
}

// LogCacheOperation logs cache operations
func (im *IntegrationManager) LogCacheOperation(operation, key string, hit bool, duration time.Duration) {
	if !im.enabled {
		status := "hit"
		if !hit {
			status = "miss"
		}
		logrus.Debugf("Cache %s: %s (%s) in %v", operation, key, status, duration)
		return
	}

	im.structuredLogger.Debug("Cache operation", map[string]interface{}{
		"operation":   operation,
		"key":         key,
		"hit":         hit,
		"duration_ms": duration.Milliseconds(),
		"timestamp":   time.Now().Unix(),
	})
}

// LogNetworkOperation logs network operations
func (im *IntegrationManager) LogNetworkOperation(
	operation, url string, statusCode int, duration time.Duration, success bool) {
	if !im.enabled {
		status := "success"
		if !success {
			status = "failed"
		}
		logrus.Debugf("Network %s: %s (%d) %s in %v", operation, url, statusCode, status, duration)
		return
	}

	level := LevelInfo
	if !success {
		level = LevelError
	}

	if level == LevelError {
		im.structuredLogger.Error("Network operation", map[string]interface{}{
			"operation":   operation,
			"url":         url,
			"status_code": statusCode,
			"duration_ms": duration.Milliseconds(),
			"success":     success,
			"timestamp":   time.Now().Unix(),
		})
	} else {
		im.structuredLogger.Info("Network operation", map[string]interface{}{
			"operation":   operation,
			"url":         url,
			"status_code": statusCode,
			"duration_ms": duration.Milliseconds(),
			"success":     success,
			"timestamp":   time.Now().Unix(),
		})
	}
}

// LogSnapshotOperation logs snapshot operations
func (im *IntegrationManager) LogSnapshotOperation(operation string, files int, duration time.Duration, success bool) {
	if !im.enabled {
		status := "success"
		if !success {
			status = "failed"
		}
		logrus.Debugf("Snapshot %s: %d files %s in %v", operation, files, status, duration)
		return
	}

	level := LevelInfo
	if !success {
		level = LevelError
	}

	if level == LevelError {
		im.structuredLogger.Error("Snapshot operation", map[string]interface{}{
			"operation":   operation,
			"files":       files,
			"duration_ms": duration.Milliseconds(),
			"success":     success,
			"timestamp":   time.Now().Unix(),
		})
	} else {
		im.structuredLogger.Info("Snapshot operation", map[string]interface{}{
			"operation":   operation,
			"files":       files,
			"duration_ms": duration.Milliseconds(),
			"success":     success,
			"timestamp":   time.Now().Unix(),
		})
	}
}

// LogError logs an error with structured context
func (im *IntegrationManager) LogError(component, operation string, err error, ctx map[string]interface{}) {
	if !im.enabled {
		logrus.Errorf("%s %s failed: %v", component, operation, err)
		return
	}

	fields := map[string]interface{}{
		"component": component,
		"operation": operation,
		"error":     err.Error(),
		"timestamp": time.Now().Unix(),
	}

	// Add additional context
	for k, v := range ctx {
		fields[k] = v
	}

	im.structuredLogger.Error("Operation failed", fields)
}

// LogPerformance logs performance metrics
func (im *IntegrationManager) LogPerformance(component, metric string, value float64, unit string) {
	if !im.enabled {
		logrus.Debugf("%s %s: %.2f %s", component, metric, value, unit)
		return
	}

	im.structuredLogger.Debug("Performance metric", map[string]interface{}{
		"component": component,
		"metric":    metric,
		"value":     value,
		"unit":      unit,
		"timestamp": time.Now().Unix(),
	})
}

// GetStructuredLogger returns the structured logger instance
func (im *IntegrationManager) GetStructuredLogger() *StructuredLogger {
	return im.structuredLogger
}

// GetEnhancedLogger returns the enhanced logger instance
func (im *IntegrationManager) GetEnhancedLogger() *EnhancedLogger {
	return im.enhancedLogger
}

// LogStatistics logs comprehensive statistics
func (im *IntegrationManager) LogStatistics() {
	if !im.enabled {
		return
	}

	// Log structured logger statistics
	if im.structuredLogger != nil {
		// Get performance report if available
		if report, err := im.structuredLogger.GetPerformanceReport(); err == nil {
			im.structuredLogger.Info("Performance report", map[string]interface{}{
				"report": report,
			})
		}

		// Get metrics report if available
		if report, err := im.structuredLogger.GetMetricsReport(); err == nil {
			im.structuredLogger.Info("Metrics report", map[string]interface{}{
				"report": report,
			})
		}
	}

	// Log enhanced logger statistics
	if im.enhancedLogger != nil {
		logrus.Info("Enhanced logger statistics logged")
	}
}

// Close closes the integration manager
func (im *IntegrationManager) Close() {
	if im.structuredLogger != nil {
		im.structuredLogger.Close()
	}
	logrus.Info("Logging integration manager closed")
}
