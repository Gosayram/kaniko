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
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Status constants
const (
	StatusCompleted = "completed"
	StatusFailed    = "failed"
	StatusSuccess   = "success"
)

// GlobalManager provides global access to structured logging across Kaniko
type GlobalManager struct {
	integrationManager *IntegrationManager
	asyncLogger        *AsyncLogger
	initialized        bool
	mutex              sync.RWMutex
}

var (
	globalManager *GlobalManager
	globalOnce    sync.Once
)

// GetGlobalManager returns the singleton global logging manager
func GetGlobalManager() *GlobalManager {
	globalOnce.Do(func() {
		globalManager = &GlobalManager{
			integrationManager: NewIntegrationManager(),
			initialized:        false,
		}
	})
	return globalManager
}

// Initialize initializes the global logging manager
func (gm *GlobalManager) Initialize(level, format string, enableStructured bool) error {
	gm.mutex.Lock()
	defer gm.mutex.Unlock()

	if gm.initialized {
		return nil
	}

	// Configure basic logging
	if err := Configure(level, format, true); err != nil {
		return err
	}

	// Enable structured logging if requested
	if enableStructured {
		gm.integrationManager.EnableStructuredLogging()
	}

	// Initialize and start async logger for non-critical logs
	gm.asyncLogger = GetAsyncLogger()
	gm.asyncLogger.Start()

	gm.initialized = true
	logrus.Info("Global logging manager initialized")
	return nil
}

// IsInitialized returns whether the global manager is initialized
func (gm *GlobalManager) IsInitialized() bool {
	gm.mutex.RLock()
	defer gm.mutex.RUnlock()
	return gm.initialized
}

// GetIntegrationManager returns the integration manager
func (gm *GlobalManager) GetIntegrationManager() *IntegrationManager {
	gm.mutex.RLock()
	defer gm.mutex.RUnlock()
	return gm.integrationManager
}

// LogBuildStart logs the start of a build process
func (gm *GlobalManager) LogBuildStart(buildID, dockerfilePath string, stages int) {
	if gm.IsInitialized() {
		gm.integrationManager.LogBuildStart(buildID, dockerfilePath, stages)
	} else {
		logrus.Infof("Starting build %s with %d stages", buildID, stages)
	}
}

// LogBuildComplete logs the completion of a build process
func (gm *GlobalManager) LogBuildComplete(buildID string, duration int64, success bool) {
	if gm.IsInitialized() {
		gm.integrationManager.LogBuildComplete(buildID,
			time.Duration(duration)*time.Millisecond, success)
	} else {
		status := StatusCompleted
		if !success {
			status = StatusFailed
		}
		logrus.Infof("Build %s %s in %dms", buildID, status, duration)
	}
}

// LogStageStart logs the start of a build stage
func (gm *GlobalManager) LogStageStart(stageIndex int, stageName, baseImage string) {
	if gm.IsInitialized() {
		gm.integrationManager.LogStageStart(stageIndex, stageName, baseImage)
	} else {
		logrus.Infof("Building stage %d: %s (base: %s)", stageIndex, stageName, baseImage)
	}
}

// LogStageComplete logs the completion of a build stage
func (gm *GlobalManager) LogStageComplete(stageIndex int, stageName string, duration int64, success bool) {
	if gm.IsInitialized() {
		gm.integrationManager.LogStageComplete(stageIndex, stageName,
			time.Duration(duration)*time.Millisecond, success)
	} else {
		status := StatusCompleted
		if !success {
			status = StatusFailed
		}
		logrus.Infof("Stage %d (%s) %s in %dms", stageIndex, stageName, status, duration)
	}
}

// LogCommandStart logs the start of a Docker command execution
func (gm *GlobalManager) LogCommandStart(commandIndex int, command, stageName string) {
	if gm.IsInitialized() {
		gm.integrationManager.LogCommandStart(commandIndex, command, stageName)
	} else {
		logrus.Infof("Executing command %d: %s", commandIndex, command)
	}
}

// LogCommandComplete logs the completion of a Docker command execution
func (gm *GlobalManager) LogCommandComplete(commandIndex int, command string, duration int64, success bool) {
	if gm.IsInitialized() {
		gm.integrationManager.LogCommandComplete(commandIndex, command,
			time.Duration(duration)*time.Millisecond, success)
	} else {
		status := StatusCompleted
		if !success {
			status = StatusFailed
		}
		logrus.Infof("Command %d %s in %dms", commandIndex, status, duration)
	}
}

// LogCacheOperation logs cache operations
func (gm *GlobalManager) LogCacheOperation(operation, key string, hit bool, duration int64) {
	if gm.IsInitialized() {
		gm.integrationManager.LogCacheOperation(operation, key, hit,
			time.Duration(duration)*time.Millisecond)
	} else {
		status := "hit"
		if !hit {
			status = "miss"
		}
		logrus.Debugf("Cache %s: %s (%s) in %dms", operation, key, status, duration)
	}
}

// LogNetworkOperation logs network operations
func (gm *GlobalManager) LogNetworkOperation(operation, url string, statusCode int, duration int64, success bool) {
	if gm.IsInitialized() {
		gm.integrationManager.LogNetworkOperation(operation, url, statusCode,
			time.Duration(duration)*time.Millisecond, success)
	} else {
		status := StatusSuccess
		if !success {
			status = StatusFailed
		}
		logrus.Debugf("Network %s: %s (%d) %s in %dms", operation, url, statusCode, status, duration)
	}
}

// LogSnapshotOperation logs snapshot operations
func (gm *GlobalManager) LogSnapshotOperation(operation string, files int, duration int64, success bool) {
	if gm.IsInitialized() {
		gm.integrationManager.LogSnapshotOperation(operation, files,
			time.Duration(duration)*time.Millisecond, success)
	} else {
		status := StatusSuccess
		if !success {
			status = StatusFailed
		}
		logrus.Debugf("Snapshot %s: %d files %s in %dms", operation, files, status, duration)
	}
}

// LogError logs an error with structured context
func (gm *GlobalManager) LogError(component, operation string, err error, context map[string]interface{}) {
	if gm.IsInitialized() {
		gm.integrationManager.LogError(component, operation, err, context)
	} else {
		logrus.Errorf("%s %s failed: %v", component, operation, err)
	}
}

// LogPerformance logs performance metrics
func (gm *GlobalManager) LogPerformance(component, metric string, value float64, unit string) {
	if gm.IsInitialized() {
		gm.integrationManager.LogPerformance(component, metric, value, unit)
	} else {
		logrus.Debugf("%s %s: %.2f %s", component, metric, value, unit)
	}
}

// LogStatistics logs comprehensive statistics
func (gm *GlobalManager) LogStatistics() {
	if gm.IsInitialized() {
		gm.integrationManager.LogStatistics()
	}
}

// Close closes the global logging manager
func (gm *GlobalManager) Close() {
	gm.mutex.Lock()
	defer gm.mutex.Unlock()

	// Stop async logger and flush all pending logs
	if gm.asyncLogger != nil {
		gm.asyncLogger.Stop()
	}

	if gm.integrationManager != nil {
		gm.integrationManager.Close()
	}

	gm.initialized = false
	logrus.Info("Global logging manager closed")
}

// GetAsyncLogger returns the async logger instance
func (gm *GlobalManager) GetAsyncLogger() *AsyncLogger {
	gm.mutex.RLock()
	defer gm.mutex.RUnlock()
	return gm.asyncLogger
}
