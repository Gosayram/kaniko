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

// Package constants defines common constants used throughout the Kaniko project
// including file paths, configuration values, and environment variable names
package constants

const (
	// RootDir is the path to the root directory
	RootDir = "/"

	// MountInfoPath is the path to the mount information file in proc filesystem
	MountInfoPath = "/proc/self/mountinfo"

	DefaultKanikoPath = "/kaniko"

	Author = "kaniko"

	// ContextTar is the default name of the tar uploaded to GCS buckets
	ContextTar = "context.tar.gz"

	// SnapshotModeTime is the time-based snapshot mode for filesystem tracking
	SnapshotModeTime = "time"
	SnapshotModeFull = "full"
	SnapshotModeRedo = "redo"

	// NoBaseImage is the scratch image
	NoBaseImage = "scratch"

	GCSBuildContextPrefix      = "gs://"
	S3BuildContextPrefix       = "s3://"
	LocalDirBuildContextPrefix = "dir://"
	GitBuildContextPrefix      = "git://"
	HTTPSBuildContextPrefix    = "https://"

	HOME = "HOME"
	// DefaultHOMEValue is the default value Docker sets for $HOME
	DefaultHOMEValue = "/root"
	RootUser         = "root"

	// Cmd represents the CMD Dockerfile instruction name
	Cmd        = "CMD"
	Entrypoint = "ENTRYPOINT"

	// Dockerignore is the name of the .dockerignore file used for file exclusion
	Dockerignore = ".dockerignore"

	// S3EndpointEnv is the environment variable name for S3 custom endpoint configuration
	S3EndpointEnv    = "S3_ENDPOINT"
	S3ForcePathStyle = "S3_FORCE_PATH_STYLE"
)

// ScratchEnvVars are the default environment variables needed for a scratch image.
var ScratchEnvVars = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}

// AzureBlobStorageHostRegEx contains regex patterns for valid Azure blob storage host suffixes
// across different Azure clouds: AzureCloud, AzureChinaCloud, AzureGermanCloud, and AzureUSGovernment
var AzureBlobStorageHostRegEx = []string{
	"https://(.+?)\\.blob\\.core\\.windows\\.net/(.+)",
	"https://(.+?)\\.blob\\.core\\.chinacloudapi\\.cn/(.+)",
	"https://(.+?)\\.blob\\.core\\.cloudapi\\.de/(.+)",
	"https://(.+?)\\.blob\\.core\\.usgovcloudapi\\.net/(.+)",
}
