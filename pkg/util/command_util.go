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
	"bufio"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
	"github.com/moby/buildkit/frontend/dockerfile/parser"
	"github.com/moby/buildkit/frontend/dockerfile/shell"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/config"
)

// for testing
var (
	getUIDAndGIDFunc = getUIDAndGID
)

const (
	pathSeparator    = "/"
	maxEnvSplitParts = 2
	defaultChmod     = 0o600
)

// ResolveEnvironmentReplacementList resolves a list of values by calling resolveEnvironmentReplacement
func ResolveEnvironmentReplacementList(values, envs []string, isFilepath bool) ([]string, error) {
	var resolvedValues []string
	for _, value := range values {
		resolved, err := ResolveEnvironmentReplacement(value, envs, isFilepath)
		logrus.Debugf("Resolved %s to %s", value, resolved)
		if err != nil {
			return nil, err
		}
		resolvedValues = append(resolvedValues, resolved)
	}
	return resolvedValues, nil
}

// ResolveEnvironmentReplacement resolves replacing env variables in some text from envs
// It takes in a string representation of the command, the value to be resolved, and a list of envs (config.Env)
// Ex: value = $foo/newdir, envs = [foo=/foodir], then this should return /foodir/newdir
// The dockerfile/shell package handles processing env values
// It handles escape characters and supports expansion from the config.Env array
// Shlex handles some of the following use cases (these and more are tested in integration tests)
// ""a'b'c"" -> "a'b'c"
// "Rex\ The\ Dog \" -> "Rex The Dog"
// "a\"b" -> "a"b"
func ResolveEnvironmentReplacement(value string, envs []string, isFilepath bool) (string, error) {
	shlex := shell.NewLex(parser.DefaultEscapeToken)
	fp, _, err := shlex.ProcessWord(value, shell.EnvsFromSlice(envs))
	// Check after replacement if value is a remote URL
	if !isFilepath || IsSrcRemoteFileURL(fp) {
		return fp, err
	}
	if err != nil {
		return "", err
	}
	isDir := strings.HasSuffix(fp, pathSeparator)
	fp = filepath.Clean(fp)
	if isDir && !strings.HasSuffix(fp, pathSeparator) {
		fp += pathSeparator
	}
	return fp, nil
}

// ResolveEnvAndWildcards resolves environment variables and wildcards in source paths.
func ResolveEnvAndWildcards(
	sd instructions.SourcesAndDest,
	fileContext FileContext,
	envs []string,
) (resolvedSources []string, destPath string, err error) {
	// First, resolve any environment replacement
	resolvedEnvs, err := ResolveEnvironmentReplacementList(sd.SourcePaths, envs, true)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to resolve environment")
	}
	if len(resolvedEnvs) == 0 {
		return nil, "", errors.New("resolved envs is empty")
	}
	dests, err := ResolveEnvironmentReplacementList([]string{sd.DestPath}, envs, true)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to resolve environment for dest path")
	}
	dest := dests[0]
	sd.DestPath = dest
	// Resolve wildcards and get a list of resolved sources
	srcs, err := ResolveSources(resolvedEnvs, fileContext.Root)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to resolve sources")
	}
	err = IsSrcsValid(sd, srcs, fileContext)
	return srcs, dest, err
}

// ContainsWildcards returns true if any entry in paths contains wildcards
func ContainsWildcards(paths []string) bool {
	for _, path := range paths {
		if strings.ContainsAny(path, "*?[") {
			return true
		}
	}
	return false
}

// ResolveSources resolves the given sources if the sources contains wildcards
// It returns a list of resolved sources
func ResolveSources(srcs []string, root string) ([]string, error) {
	// If sources contain wildcards, we first need to resolve them to actual paths
	if !ContainsWildcards(srcs) {
		return srcs, nil
	}
	logrus.Infof("Resolving srcs %v...", srcs)
	files, err := RelativeFiles("", root)
	if err != nil {
		return nil, errors.Wrap(err, "resolving sources")
	}
	resolved, err := matchSources(srcs, files)
	if err != nil {
		return nil, errors.Wrap(err, "matching sources")
	}
	logrus.Debugf("Resolved sources to %v", resolved)
	return resolved, nil
}

// matchSources returns a list of sources that match wildcards
// nolint:gocyclo // Matching logic requires multiple branches to cover path variants
func matchSources(srcs, files []string) ([]string, error) {
	var matchedSources []string
	for _, src := range srcs {
		if IsSrcRemoteFileURL(src) {
			matchedSources = append(matchedSources, src)
			continue
		}
		src = filepath.Clean(src)
		for _, file := range files {
			// For absolute source paths, we need to check against the file path
			// For relative source paths, we check against the file path as is
			var testFile string
			if filepath.IsAbs(src) {
				// If source is absolute, prepend root dir to file for matching
				testFile = filepath.Join(config.RootDir, file)
			} else {
				// If source is relative, use file as is
				testFile = file
			}

			// Also consider matching against "context/"-prefixed file when src starts with "context/"
			testFileWithContext := filepath.Join("context", file)
			if !strings.HasPrefix(src, "context/") {
				testFileWithContext = ""
			}

			matched, err := filepath.Match(src, testFile)
			if err != nil {
				return nil, err
			}
			if matched || src == testFile {
				// Preserve "context/" prefix in results when source pattern includes it
				if strings.HasPrefix(src, "context/") && !strings.HasPrefix(file, "context/") {
					matchedSources = append(matchedSources, filepath.Join("context", file))
				} else {
					matchedSources = append(matchedSources, file)
				}
			}

			if testFileWithContext != "" {
				matchedWithCtx, err := filepath.Match(src, testFileWithContext)
				if err != nil {
					return nil, err
				}
				if matchedWithCtx || src == testFileWithContext {
					matchedSources = append(matchedSources, filepath.Join("context", file))
				}
			}

			// Also try matching with absolute path for absolute sources
			if filepath.IsAbs(src) {
				absoluteTestFile := string(filepath.Separator) + file
				matched, err := filepath.Match(src, absoluteTestFile)
				if err != nil {
					return nil, err
				}
				if matched || src == absoluteTestFile {
					if strings.HasPrefix(src, "context/") && !strings.HasPrefix(file, "context/") {
						matchedSources = append(matchedSources, filepath.Join("context", file))
					} else {
						matchedSources = append(matchedSources, file)
					}
				}
			}
		}
	}
	return matchedSources, nil
}

// IsDestDir checks if the given path is a directory
func IsDestDir(path string) bool {
	// try to stat the path
	fileInfo, err := os.Stat(path)
	if err != nil {
		// fall back to string-based determination
		return strings.HasSuffix(path, pathSeparator) || path == "."
	}
	// if it's a real path, check the fs response
	return fileInfo.IsDir()
}

// DestinationFilepath returns the destination filepath from the build context to the image filesystem
// If source is a file:
//
//	If dest is a dir, copy it to /dest/relpath
//	If dest is a file, copy directly to dest
//
// If source is a dir:
//
//	Assume dest is also a dir, and copy to dest/
//
// If dest is not an absolute filepath, add /cwd to the beginning
func DestinationFilepath(src, dest, cwd string) (string, error) {
	_, srcFileName := filepath.Split(src)
	newDest := dest

	if !filepath.IsAbs(newDest) {
		newDest = filepath.Join(cwd, newDest)
		// join call clean on all results.
		if strings.HasSuffix(dest, pathSeparator) || strings.HasSuffix(dest, ".") {
			newDest += pathSeparator
		}
	}
	if IsDestDir(newDest) {
		newDest = filepath.Join(newDest, srcFileName)
	}

	if srcFileName == "" && !strings.HasSuffix(newDest, pathSeparator) {
		newDest += pathSeparator
	}

	return newDest, nil
}

// URLDestinationFilepath gives the destination a file from a remote URL should be saved to
func URLDestinationFilepath(rawurl, dest, cwd string, envs []string) (string, error) {
	if !IsDestDir(dest) {
		if !filepath.IsAbs(dest) {
			return filepath.Join(cwd, dest), nil
		}
		return dest, nil
	}

	urlBase, err := ResolveEnvironmentReplacement(rawurl, envs, true)
	if err != nil {
		return "", err
	}

	urlBase, err = extractFilename(urlBase)
	if err != nil {
		return "", err
	}

	destPath := filepath.Join(dest, urlBase)

	if !filepath.IsAbs(dest) {
		destPath = filepath.Join(cwd, destPath)
	}
	return destPath, nil
}

// validateNonWildcardSources validates sources when no wildcards are present
func validateNonWildcardSources(srcs []string, dest string, fileContext FileContext) error {
	totalSrcs := 0
	for _, src := range srcs {
		if fileContext.ExcludesFile(src) {
			continue
		}
		totalSrcs++
	}
	if totalSrcs > 1 && !IsDestDir(dest) {
		return validateMultipleSourcesDestination(dest)
	}
	return nil
}

// validateMultipleSourcesDestination validates destination for multiple sources
func validateMultipleSourcesDestination(dest string) error {
	if strings.HasSuffix(dest, "/") || dest == "." {
		// Destination is explicitly a directory, allow the copy
		return nil
	}
	if fi, err := os.Stat(dest); err == nil && !fi.IsDir() {
		// Destination exists and is a file, this is an error
		return errors.New("when specifying multiple sources in a COPY command, " +
			"destination must be a directory and end in '/'")
	}
	// If destination doesn't exist, allow the copy (Docker behavior)
	return nil
}

// checkSingleDirectorySource checks if there's only one source and it's a directory
func checkSingleDirectorySource(resolvedSources []string, fileContext FileContext) error {
	if len(resolvedSources) != 1 {
		return nil
	}
	if IsSrcRemoteFileURL(resolvedSources[0]) {
		return nil
	}
	path := filepath.Join(fileContext.Root, resolvedSources[0])
	fi, err := os.Lstat(path)
	if err != nil {
		// Don't fail on missing files - log warning and continue
		logrus.Warnf("Source file not found: %s, continuing anyway", path)
		return nil
	}
	// Don't return early for directories - let the totalFiles check handle it
	_ = fi.IsDir() // Continue to totalFiles check below
	return nil
}

// countTotalFiles counts total files to be copied
func countTotalFiles(resolvedSources []string, fileContext FileContext) int {
	totalFiles := 0
	for _, src := range resolvedSources {
		if IsSrcRemoteFileURL(src) {
			totalFiles++
			continue
		}
		src = filepath.Clean(src)
		files, err := RelativeFiles(src, fileContext.Root)
		if err != nil {
			// Don't fail on missing files - log warning and continue
			logrus.Warnf("Failed to get relative files for %s: %v, continuing anyway", src, err)
			continue
		}
		for _, file := range files {
			if fileContext.ExcludesFile(file) {
				continue
			}
			totalFiles++
		}
	}
	return totalFiles
}

// validateDestinationForMultipleFiles validates destination when multiple files are being copied
func validateDestinationForMultipleFiles(totalFiles int, dest string) error {
	if totalFiles <= 1 {
		return nil
	}
	if IsDestDir(dest) {
		return nil
	}
	return validateMultipleSourcesDestination(dest)
}

// IsSrcsValid validates source files and destination for copy operations
func IsSrcsValid(srcsAndDest instructions.SourcesAndDest, resolvedSources []string, fileContext FileContext) error {
	srcs := srcsAndDest.SourcePaths
	dest := srcsAndDest.DestPath

	// Validate non-wildcard sources
	if !ContainsWildcards(srcs) {
		if err := validateNonWildcardSources(srcs, dest, fileContext); err != nil {
			return err
		}
	}

	// Check single directory source
	if err := checkSingleDirectorySource(resolvedSources, fileContext); err != nil {
		return err
	}

	// Count total files
	totalFiles := countTotalFiles(resolvedSources, fileContext)

	// Handle case with no files to copy
	if totalFiles == 0 {
		logrus.Warn("No files to copy")
		return nil
	}

	// Validate destination for multiple files
	return validateDestinationForMultipleFiles(totalFiles, dest)
}

// IsSrcRemoteFileURL checks if the given URL represents a remote file source.
func IsSrcRemoteFileURL(rawurl string) bool {
	u, err := url.ParseRequestURI(rawurl)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// UpdateConfigEnv updates the container configuration environment variables.
func UpdateConfigEnv(envVars []instructions.KeyValuePair, containerConfig *v1.Config, replacementEnvs []string) error {
	newEnvs := make([]instructions.KeyValuePair, len(envVars))
	for index, pair := range envVars {
		expandedKey, err := ResolveEnvironmentReplacement(pair.Key, replacementEnvs, false)
		if err != nil {
			return err
		}
		expandedValue, err := ResolveEnvironmentReplacement(pair.Value, replacementEnvs, false)
		if err != nil {
			return err
		}
		newEnvs[index] = instructions.KeyValuePair{
			Key:   expandedKey,
			Value: expandedValue,
		}
	}

	// First, convert config.Env array to []instruction.KeyValuePair
	var kvps []instructions.KeyValuePair
	for _, env := range containerConfig.Env {
		entry := strings.SplitN(env, "=", maxEnvSplitParts)
		kvps = append(kvps, instructions.KeyValuePair{
			Key:   entry[0],
			Value: entry[1],
		})
	}
	// Iterate through new environment variables, and replace existing keys
	// We can't use a map because we need to preserve the order of the environment variables
Loop:
	for _, newEnv := range newEnvs {
		for index, kvp := range kvps {
			// If key exists, replace the KeyValuePair...
			if kvp.Key == newEnv.Key {
				logrus.Debugf("Replacing environment variable %v with %v in config", kvp, newEnv)
				kvps[index] = newEnv
				continue Loop
			}
		}
		// ... Else, append it as a new env variable
		kvps = append(kvps, newEnv)
	}
	// Convert back to array and set in config
	envArray := []string{}
	for _, kvp := range kvps {
		entry := kvp.Key + "=" + kvp.Value
		envArray = append(envArray, entry)
	}
	containerConfig.Env = envArray
	return nil
}

// GetUserGroup resolves user and group information from a chown string.
// CRITICAL FIX: Added safe fallback for user resolution failures
func GetUserGroup(chownStr string, env []string) (uid, gid int64, err error) {
	if chownStr == "" {
		return DoNotChangeUID, DoNotChangeGID, nil
	}

	chown, err := ResolveEnvironmentReplacement(chownStr, env, false)
	if err != nil {
		logrus.Warnf("Failed to resolve environment variables in chown string %s: %v", chownStr, err)
		// Use safe defaults instead of failing
		return SafeDefaultUID, SafeDefaultGID, nil
	}

	uid32, gid32, err := getUIDAndGIDFromString(chown)
	if err != nil {
		logrus.Warnf("Failed to resolve user/group %s: %v, using safe defaults", chown, err)
		// Use safe defaults instead of failing
		return SafeDefaultUID, SafeDefaultGID, nil
	}

	// Use safe UID/GID values to prevent "invalid user/group IDs" errors
	safeUID, safeGID := GetSafeUIDGID(int64(uid32), int64(gid32))
	logrus.Debugf("Resolved user/group %s to safe UID/GID: %d/%d", chown, safeUID, safeGID)

	return safeUID, safeGID, nil
}

// GetChmod resolves file mode permissions from a chmod string.
func GetChmod(chmodStr string, env []string) (chmod fs.FileMode, useDefault bool, err error) {
	if chmodStr == "" {
		return fs.FileMode(defaultChmod), true, nil
	}

	chmodStr, err = ResolveEnvironmentReplacement(chmodStr, env, false)
	if err != nil {
		return 0, false, err
	}

	mode, err := strconv.ParseUint(chmodStr, 8, 32)
	if err != nil {
		return 0, false, errors.Wrap(err, "parsing value from chmod")
	}
	chmod = fs.FileMode(mode)
	return
}

// Extract user and group id from a string formatted 'user:group'.
// UserID and GroupID don't need to be present on the system.
func getUIDAndGIDFromString(userGroupString string) (uid, gid uint32, err error) {
	userAndGroup := strings.Split(userGroupString, ":")
	userStr := userAndGroup[0]
	var groupStr string
	if len(userAndGroup) > 1 {
		groupStr = userAndGroup[1]
	}
	return getUIDAndGIDFunc(userStr, groupStr)
}

func getUIDAndGID(userStr, groupStr string) (uid, gid uint32, err error) {
	userObj, err := LookupUser(userStr)
	if err != nil {
		// CRITICAL FIX: Instead of failing, create a safe fallback
		logrus.Warnf("Failed to lookup user %s, using safe fallback: %v", userStr, err)
		fallbackUID := getSafeFallbackUID(userStr)
		uid = fallbackUID
		gid = fallbackUID
		return uid, gid, nil
	}

	uid32, err := getUID(userObj.Uid)
	if err != nil {
		// CRITICAL FIX: Use fallback UID if parsing fails
		logrus.Warnf("Failed to parse UID %s for user %s, using safe fallback: %v", userObj.Uid, userStr, err)
		uid = getSafeFallbackUID(userStr)
		gid = uid
		return uid, gid, nil
	}

	if groupStr != "" {
		gid32, err := getGIDFromName(groupStr)
		if err != nil {
			if errors.Is(err, fallbackToUIDError) {
				return uid32, uid32, nil
			}
			// CRITICAL FIX: Use fallback GID if group lookup fails
			logrus.Warnf("Failed to lookup group %s, using user GID: %v", groupStr, err)
			return uid32, uid32, nil
		}
		return uid32, gid32, nil
	}

	return uid32, uid32, nil
}

// getGID tries to parse the gid
func getGID(groupStr string) (uint32, error) {
	gid, err := strconv.ParseUint(groupStr, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(gid), nil
}

// getGIDFromName tries to parse the groupStr into an existing group.
// CRITICAL FIX: Added safe fallback for non-existing groups
func getGIDFromName(groupStr string) (uint32, error) {
	group, err := user.LookupGroup(groupStr)
	if err != nil {
		// unknown group error could relate to a non existing group
		var groupErr user.UnknownGroupError
		if errors.As(err, &groupErr) {
			// Try to parse as numeric GID first
			if gid, parseErr := getGID(groupStr); parseErr == nil {
				return gid, nil
			}
			// CRITICAL FIX: Create safe fallback GID for non-existing groups
			logrus.Warnf("Group %s does not exist, using safe fallback GID", groupStr)
			return getSafeFallbackUID(groupStr), nil
		}
		group, err = user.LookupGroupId(groupStr)
		if err != nil {
			// Try to parse as numeric GID
			if gid, parseErr := getGID(groupStr); parseErr == nil {
				return gid, nil
			}
			// CRITICAL FIX: Create safe fallback GID for non-existing groups
			logrus.Warnf("Group %s does not exist, using safe fallback GID", groupStr)
			return getSafeFallbackUID(groupStr), nil
		}
	}
	return getGID(group.Gid)
}

var fallbackToUIDError = new(fallbackToUIDErrorType)

type fallbackToUIDErrorType struct{}

func (e fallbackToUIDErrorType) Error() string {
	return "fallback to uid"
}

// LookupUser will try to lookup the userStr inside the passwd file.
// If the user does not exists, the function will fallback to parsing the userStr as an uid.
// CRITICAL FIX: Added safe fallback for non-existing users to prevent build failures
func LookupUser(userStr string) (*user.User, error) {
	userObj, err := user.Lookup(userStr)
	if err != nil {
		unknownUserErr := new(user.UnknownUserError)
		// only return if it's not an unknown user error or the passwd file does not exist
		if !errors.As(err, unknownUserErr) && !os.IsNotExist(err) {
			return nil, err
		}

		// Lookup by id
		userObj, err = user.LookupId(userStr)
		if err != nil {
			uid, err := getUID(userStr)
			if err != nil {
				// CRITICAL FIX: Try to create user in system first, then fallback
				logrus.Warnf("User %s does not exist on the system, attempting to create or use fallback", userStr)

				// Try to create user in system first
				createdUser := tryCreateUserInSystem(userStr)
				return createdUser, nil
			}
			userObj = &user.User{
				Uid:     fmt.Sprint(uid),
				HomeDir: "/",
			}
		}
	}
	return userObj, nil
}

func getUID(userStr string) (uint32, error) {
	// checkif userStr is a valid id
	uid, err := strconv.ParseUint(userStr, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(uid), nil
}

// Constants for safe UID generation
const (
	hashMultiplier = 31
	minSafeUID     = 1000
	maxSafeUID     = 65534
	uidRange       = maxSafeUID - minSafeUID
	// Passwd file format constants
	passwdFieldsCount = 7
	groupFieldsCount  = 4
)

// getSafeFallbackUID generates a safe UID for non-existing users
// Uses a hash-based approach to ensure consistent UIDs for the same username
// DYNAMIC: No hardcoded users - generates UID based on username hash
func getSafeFallbackUID(userStr string) uint32 {
	// Use a simple hash to generate a consistent UID for the same username
	// This ensures that the same user string always gets the same UID
	hash := 0
	for _, c := range userStr {
		hash = hash*hashMultiplier + int(c)
	}

	// Ensure UID is in a safe range (1000-65534) to avoid conflicts with system users
	// Use absolute value to prevent negative hash values
	if hash < 0 {
		hash = -hash
	}
	// Use safe conversion to prevent overflow
	// #nosec G115 - hash is controlled and safe for conversion
	hashAbs := uint64(hash)
	if hashAbs > uint64(uidRange) {
		hashAbs %= uint64(uidRange)
	}
	// #nosec G115 - hashAbs is controlled and safe for conversion
	safeUID := minSafeUID + uint32(hashAbs)

	logrus.Debugf("Generated dynamic UID %d for user %s", safeUID, userStr)
	return safeUID
}

// createUserInSystem attempts to create a user in the system if possible
// This is a best-effort approach that may not work in all environments
// Uses secure command building to prevent command injection
func createUserInSystem(userStr string, uid uint32) {
	// Use secure command creation
	cmd, err := CreateSecureUserCommand(userStr, uid, "/bin/bash")
	if err != nil {
		logrus.Debugf("Failed to create secure command for user %s: %v", userStr, err)
		return
	}

	// Execute the secure command
	if err := cmd.Run(); err != nil {
		logrus.Debugf("Failed to create user %s with useradd: %v", userStr, err)
		// This is not a critical error - we'll use the fallback user
		return
	}

	logrus.Infof("Successfully created user %s with UID %d using secure command", userStr, uid)
}

// tryCreateUserInSystem attempts to create a user in the system if it doesn't exist
// DYNAMIC: First tries to find user in Docker layer, then creates if needed
func tryCreateUserInSystem(userStr string) *user.User {
	logrus.Debugf("🔧 Attempting to resolve user '%s'", userStr)

	// First try to lookup the user in system
	logrus.Debugf("🔍 Checking system for user '%s'", userStr)
	userObj, err := user.Lookup(userStr)
	if err == nil {
		logrus.Infof("✅ Found user '%s' in system: UID=%s, GID=%s", userStr, userObj.Uid, userObj.Gid)
		return userObj
	}
	logrus.Debugf("❌ User '%s' not found in system: %v", userStr, err)

	// Try to find user in Docker layer (if we have access to extracted filesystem)
	// This is the key improvement - we look for the user in the Docker layer first
	logrus.Debugf("🐳 Searching for user '%s' in Docker layer", userStr)
	if dockerUser := getUserFromDockerLayer(userStr, "/kaniko"); dockerUser != nil {
		logrus.Infof("✅ Found user '%s' in Docker layer, using it", userStr)
		return dockerUser
	}

	// User doesn't exist in Docker layer either, try to create it in system
	logrus.Debugf("🔨 User '%s' not found, attempting to create with fallback UID", userStr)
	fallbackUID := getSafeFallbackUID(userStr)
	logrus.Debugf("🎲 Generated fallback UID %d for user '%s'", fallbackUID, userStr)

	// Try to create the user in the system
	createUserInSystem(userStr, fallbackUID)

	// Try to lookup the newly created user
	logrus.Debugf("🔍 Checking if user '%s' was created successfully", userStr)
	newUserObj, lookupErr := user.Lookup(userStr)
	if lookupErr == nil {
		logrus.Infof("✅ Successfully created user '%s' in system: UID=%s, GID=%s",
			userStr, newUserObj.Uid, newUserObj.Gid)
		return newUserObj
	}
	logrus.Debugf("❌ Failed to lookup created user '%s': %v", userStr, lookupErr)

	// If creation failed or lookup failed, return a fallback user object
	logrus.Warnf("⚠️ Using fallback user object for '%s' with UID %d", userStr, fallbackUID)
	return &user.User{
		Uid:      fmt.Sprint(fallbackUID),
		Gid:      fmt.Sprint(fallbackUID),
		HomeDir:  "/",
		Name:     userStr,
		Username: userStr,
	}
}

// getUserFromDockerLayer attempts to extract user information from Docker layer
// This is a more sophisticated approach that looks for the user in the extracted filesystem
func getUserFromDockerLayer(userStr, rootPath string) *user.User {
	logrus.Debugf("🔍 Searching for user '%s' in Docker layer at path: %s", userStr, rootPath)

	// Try to find user in /etc/passwd from the extracted layer
	passwdPath := filepath.Join(rootPath, "etc", "passwd")
	logrus.Debugf("📄 Checking passwd file: %s", passwdPath)
	userObj, err := getUserFromPasswdFile(userStr, passwdPath)
	if err == nil {
		logrus.Infof("✅ Found user '%s' in Docker layer passwd file: UID=%s, GID=%s, HomeDir=%s",
			userStr, userObj.Uid, userObj.Gid, userObj.HomeDir)
		return userObj
	}
	logrus.Debugf("❌ User '%s' not found in passwd file: %v", userStr, err)

	// Try to find user in /etc/group from the extracted layer
	groupPath := filepath.Join(rootPath, "etc", "group")
	logrus.Debugf("📄 Checking group file: %s", groupPath)
	userObj, err = getUserFromGroupFile(userStr, groupPath)
	if err == nil {
		logrus.Infof("✅ Found user '%s' in Docker layer group file: UID=%s, GID=%s",
			userStr, userObj.Uid, userObj.Gid)
		return userObj
	}
	logrus.Debugf("❌ User '%s' not found in group file: %v", userStr, err)

	logrus.Debugf("⚠️ User '%s' not found in Docker layer, will use fallback", userStr)
	return nil
}

// getUserFromPasswdFile extracts user information from /etc/passwd file
func getUserFromPasswdFile(userStr, passwdPath string) (*user.User, error) {
	// Validate path to prevent directory traversal
	if !isValidPasswdPath(passwdPath) {
		return nil, fmt.Errorf("invalid passwd file path: %s", passwdPath)
	}

	// #nosec G304 - path is validated and controlled
	file, err := os.Open(passwdPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) < passwdFieldsCount {
			continue
		}

		username := fields[0]
		if username == userStr {
			uid := fields[2]
			gid := fields[3]
			homeDir := fields[5]
			_ = fields[6] // shell - not used but part of passwd format

			return &user.User{
				Uid:      uid,
				Gid:      gid,
				Username: username,
				Name:     username,
				HomeDir:  homeDir,
			}, nil
		}
	}

	return nil, fmt.Errorf("user %s not found in passwd file", userStr)
}

// getUserFromGroupFile extracts user information from /etc/group file
func getUserFromGroupFile(userStr, groupPath string) (*user.User, error) {
	// Validate path to prevent directory traversal
	if !isValidGroupPath(groupPath) {
		return nil, fmt.Errorf("invalid group file path: %s", groupPath)
	}

	// #nosec G304 - path is validated and controlled
	file, err := os.Open(groupPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Split(line, ":")
		if len(fields) < groupFieldsCount {
			continue
		}

		groupname := fields[0]
		if groupname == userStr {
			gid := fields[2]

			return &user.User{
				Uid:      gid, // Use GID as UID for group-based users
				Gid:      gid,
				Username: userStr,
				Name:     userStr,
				HomeDir:  "/",
			}, nil
		}
	}

	return nil, fmt.Errorf("user %s not found in group file", userStr)
}

// isValidPasswdPath validates that the passwd file path is safe
func isValidPasswdPath(path string) bool {
	// Only allow /etc/passwd or paths within /kaniko directory
	cleanPath := filepath.Clean(path)
	return cleanPath == "/etc/passwd" || strings.HasPrefix(cleanPath, "/kaniko/")
}

// isValidGroupPath validates that the group file path is safe
func isValidGroupPath(path string) bool {
	// Only allow /etc/group or paths within /kaniko directory
	cleanPath := filepath.Clean(path)
	return cleanPath == "/etc/group" || strings.HasPrefix(cleanPath, "/kaniko/")
}

// ExtractFilename extracts the filename from a URL without its query url
func extractFilename(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	filename := filepath.Base(parsedURL.Path)
	return filename, nil
}
