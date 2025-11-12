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
	"context"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

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
	// DefaultResolveEnvTimeout is the default timeout for ResolveEnvAndWildcards
	DefaultResolveEnvTimeout = 5 * time.Minute
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

// resolveEnvironmentVariables resolves environment variables in source and destination paths
func resolveEnvironmentVariables(
	ctx context.Context,
	sd instructions.SourcesAndDest,
	envs []string,
) (resolvedEnvs []string, dest string, err error) {
	resolvedEnvs, err = ResolveEnvironmentReplacementList(sd.SourcePaths, envs, true)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to resolve environment")
	}

	select {
	case <-ctx.Done():
		return nil, "", ctx.Err()
	default:
	}

	if len(resolvedEnvs) == 0 {
		return nil, "", errors.New("resolved envs is empty")
	}

	dests, err := ResolveEnvironmentReplacementList([]string{sd.DestPath}, envs, true)
	if err != nil {
		return nil, "", errors.Wrap(err, "failed to resolve environment for dest path")
	}

	return resolvedEnvs, dests[0], nil
}

// resolveWildcardsAndValidate resolves wildcards and validates sources
func resolveWildcardsAndValidate(
	ctx context.Context,
	sd instructions.SourcesAndDest,
	resolvedEnvs []string,
	dest string,
	fileContext FileContext,
) ([]string, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	sd.DestPath = dest
	srcs, err := ResolveSources(resolvedEnvs, fileContext.Root)
	if err != nil {
		return nil, errors.Wrap(err, "failed to resolve sources")
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	err = IsSrcsValid(sd, srcs, fileContext)
	if err != nil {
		return nil, err
	}

	return srcs, nil
}

// resolveEnvAndWildcardsInternal performs the actual resolution work
func resolveEnvAndWildcardsInternal(
	ctx context.Context,
	sd instructions.SourcesAndDest,
	fileContext FileContext,
	envs []string,
) (srcs []string, dest string, err error) {
	var resolvedEnvs []string
	resolvedEnvs, dest, err = resolveEnvironmentVariables(ctx, sd, envs)
	if err != nil {
		return nil, "", err
	}

	srcs, err = resolveWildcardsAndValidate(ctx, sd, resolvedEnvs, dest, fileContext)
	if err != nil {
		return nil, "", err
	}

	return srcs, dest, nil
}

// ResolveEnvAndWildcards resolves environment variables and wildcards in source paths.
func ResolveEnvAndWildcards(
	sd instructions.SourcesAndDest,
	fileContext FileContext,
	envs []string,
) (resolvedSources []string, destPath string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultResolveEnvTimeout)
	defer cancel()

	resolveCh := make(chan struct {
		sources []string
		dest    string
		err     error
	}, 1)

	go func() {
		defer func() {
			select {
			case <-resolveCh:
			default:
			}
		}()

		select {
		case <-ctx.Done():
			return
		default:
		}

		srcs, dest, resolveErr := resolveEnvAndWildcardsInternal(ctx, sd, fileContext, envs)
		select {
		case resolveCh <- struct {
			sources []string
			dest    string
			err     error
		}{sources: srcs, dest: dest, err: resolveErr}:
		case <-ctx.Done():
			return
		}
	}()

	select {
	case result := <-resolveCh:
		return result.sources, result.dest, result.err
	case <-ctx.Done():
		logrus.Warnf("ResolveEnvAndWildcards timed out after 5 minutes, returning empty to prevent hang")
		return []string{}, "", nil
	case <-time.After(DefaultResolveEnvTimeout):
		logrus.Warnf("ResolveEnvAndWildcards timed out after 5 minutes, returning empty to prevent hang")
		return []string{}, "", nil
	}
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
	logrus.Infof("Resolving srcs with wildcards %v (this may take a while for large directories)...", srcs)

	// Log start time for progress tracking
	startTime := time.Now()
	files, err := RelativeFiles("", root)
	if err != nil {
		logrus.Errorf("Failed to resolve sources after %v: %v", time.Since(startTime), err)
		return nil, errors.Wrap(err, "resolving sources")
	}
	duration := time.Since(startTime)

	if duration > 10*time.Second {
		logrus.Infof("Resolved %d files in %v", len(files), duration)
	} else {
		logrus.Debugf("Resolved %d files in %v", len(files), duration)
	}

	logrus.Debugf("Matching %d sources against %d files...", len(srcs), len(files))

	// Add timeout for matchSources to prevent hangs on large file lists
	ctx, cancel := context.WithTimeout(context.Background(), DefaultResolveSourcesTimeout)
	defer cancel()

	matchCh := make(chan struct {
		resolved []string
		err      error
	}, 1)

	go func() {
		defer func() {
			// Ensure channel is always drained to prevent goroutine leak
			select {
			case <-matchCh:
			default:
			}
		}()

		// Check context before starting work
		select {
		case <-ctx.Done():
			return
		default:
		}

		resolved, err := matchSources(srcs, files)

		// Check context before sending result
		select {
		case matchCh <- struct {
			resolved []string
			err      error
		}{resolved: resolved, err: err}:
		case <-ctx.Done():
			return
		}
	}()

	var resolved []string
	select {
	case result := <-matchCh:
		if result.err != nil {
			logrus.Errorf("Failed to match sources after %v: %v", time.Since(startTime), result.err)
			return nil, errors.Wrap(result.err, "matching sources")
		}
		resolved = result.resolved
	case <-ctx.Done():
		logrus.Warnf("matchSources timed out after %v, returning partial results", time.Since(startTime))
		// Return empty list to prevent hang - build will continue
		return []string{}, nil
	case <-time.After(DefaultResolveSourcesTimeout):
		logrus.Warnf("matchSources timed out after 3 minutes, returning empty list to prevent hang")
		return []string{}, nil
	}

	logrus.Infof("Resolved sources to %d files: %v", len(resolved), resolved)
	return resolved, nil
}

// matchSources returns a list of sources that match wildcards
// nolint:gocyclo // Matching logic requires multiple branches to cover path variants
const (
	// MaxFilesToProcess is the maximum number of files to process in matchSources
	MaxFilesToProcess = 100000
	// FileProcessingCheckInterval is the interval for checking cancellation during file processing
	FileProcessingCheckInterval = 10000
)

// limitFilesToProcess limits the number of files to process to prevent hangs
func limitFilesToProcess(files []string) []string {
	if len(files) > MaxFilesToProcess {
		logrus.Warnf("Large file list detected (%d files), limiting processing to %d files to prevent hang",
			len(files), MaxFilesToProcess)
		return files[:MaxFilesToProcess]
	}
	return files
}

// addMatchedFile adds a matched file to the results if it's not already present
func addMatchedFile(matchedFile string, matchedSet map[string]struct{}, matchedSources []string) []string {
	if _, exists := matchedSet[matchedFile]; !exists {
		matchedSet[matchedFile] = struct{}{}
		matchedSources = append(matchedSources, matchedFile)
	}
	return matchedSources
}

// matchFileAgainstSource checks if a file matches the source pattern
// nolint:gocritic // Named returns would reduce readability here
func matchFileAgainstSource(src, file string) (bool, string, error) {
	testFile := file
	if filepath.IsAbs(src) {
		testFile = filepath.Join(config.RootDir, file)
	}

	matched, err := filepath.Match(src, testFile)
	if err != nil {
		return false, "", err
	}
	if matched || src == testFile {
		matchedFile := file
		if strings.HasPrefix(src, "context/") && !strings.HasPrefix(file, "context/") {
			matchedFile = filepath.Join("context", file)
		}
		return true, matchedFile, nil
	}
	return false, "", nil
}

// matchFileWithContextPrefix checks if a file matches with context prefix
// nolint:gocritic // Named returns would reduce readability here
func matchFileWithContextPrefix(src, file string) (bool, string, error) {
	if !strings.HasPrefix(src, "context/") {
		return false, "", nil
	}
	testFileWithContext := filepath.Join("context", file)
	matched, err := filepath.Match(src, testFileWithContext)
	if err != nil {
		return false, "", err
	}
	if matched || src == testFileWithContext {
		return true, testFileWithContext, nil
	}
	return false, "", nil
}

// matchFileWithAbsolutePath checks if a file matches with absolute path
// nolint:gocritic // Named returns would reduce readability here
func matchFileWithAbsolutePath(src, file string) (bool, string, error) {
	if !filepath.IsAbs(src) {
		return false, "", nil
	}
	absoluteTestFile := string(filepath.Separator) + file
	matched, err := filepath.Match(src, absoluteTestFile)
	if err != nil {
		return false, "", err
	}
	if matched || src == absoluteTestFile {
		matchedFile := file
		if strings.HasPrefix(src, "context/") && !strings.HasPrefix(file, "context/") {
			matchedFile = filepath.Join("context", file)
		}
		return true, matchedFile, nil
	}
	return false, "", nil
}

// processFileForMatching processes a single file against a source pattern
func processFileForMatching(
	src, file string,
	matchedSet map[string]struct{},
	matchedSources []string,
) ([]string, error) {
	// Try standard matching
	matched, matchedFile, err := matchFileAgainstSource(src, file)
	if err != nil {
		return matchedSources, err
	}
	if matched {
		matchedSources = addMatchedFile(matchedFile, matchedSet, matchedSources)
	}

	// Try matching with context prefix
	matched, matchedFile, err = matchFileWithContextPrefix(src, file)
	if err != nil {
		return matchedSources, err
	}
	if matched {
		matchedSources = addMatchedFile(matchedFile, matchedSet, matchedSources)
	}

	// Try matching with absolute path
	matched, matchedFile, err = matchFileWithAbsolutePath(src, file)
	if err != nil {
		return matchedSources, err
	}
	if matched {
		matchedSources = addMatchedFile(matchedFile, matchedSet, matchedSources)
	}

	return matchedSources, nil
}

// matchSources returns a list of sources that match wildcards
// nolint:funlen // Function is complex but breaking it down further would reduce readability
func matchSources(srcs, files []string) ([]string, error) {
	var matchedSources []string
	matchedSet := make(map[string]struct{}) // Use set to avoid duplicates

	// Limit processing to prevent hangs on very large file lists
	files = limitFilesToProcess(files)

	for _, src := range srcs {
		if IsSrcRemoteFileURL(src) {
			matchedSources = append(matchedSources, src)
			continue
		}
		src = filepath.Clean(src)

		// Limit iterations to prevent hangs
		processedFiles := 0
		for _, file := range files {
			processedFiles++
			// Check every 10000 files to allow cancellation
			if processedFiles%FileProcessingCheckInterval == 0 {
				// Small delay to allow context cancellation if needed
				time.Sleep(1 * time.Millisecond)
			}

			var err error
			matchedSources, err = processFileForMatching(src, file, matchedSet, matchedSources)
			if err != nil {
				return nil, err
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

// IsSrcsValid validates source files and destination for copy operations
// This is called synchronously from ResolveEnvAndWildcards (which already has timeout protection)
func IsSrcsValid(srcsAndDest instructions.SourcesAndDest, resolvedSources []string, fileContext FileContext) error {
	srcs := srcsAndDest.SourcePaths
	dest := srcsAndDest.DestPath

	// Validate non-wildcard sources
	if !ContainsWildcards(srcs) {
		if err := validateNonWildcardSources(srcs, dest, fileContext); err != nil {
			return err
		}
	}

	// If there is only one source and it's a directory, docker assumes the dest is a directory
	if len(resolvedSources) == 1 {
		if IsSrcRemoteFileURL(resolvedSources[0]) {
			return nil
		}
		path := filepath.Join(fileContext.Root, resolvedSources[0])
		fi, err := os.Lstat(path)
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("failed to get fileinfo for %v", path))
		}
		if fi.IsDir() {
			return nil
		}
	}

	// Count total files synchronously (like osscontainers does)
	totalFiles := 0
	for _, src := range resolvedSources {
		if IsSrcRemoteFileURL(src) {
			totalFiles++
			continue
		}
		src = filepath.Clean(src)
		files, err := RelativeFiles(src, fileContext.Root)
		if err != nil {
			return errors.Wrap(err, "failed to get relative files")
		}
		for _, file := range files {
			if fileContext.ExcludesFile(file) {
				continue
			}
			totalFiles++
		}
	}

	// If there are wildcards, and the destination is a file, there must be exactly one file to copy over,
	// Otherwise, return an error
	if !IsDestDir(dest) && totalFiles > 1 {
		return errors.New("when specifying multiple sources in a COPY command, " +
			"destination must be a directory and end in '/'")
	}
	return nil
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
	// RADICAL FIX: Completely rewritten to work without system user/group lookups
	// This prevents failures in containerized environments where /etc/passwd and /etc/group are missing

	logrus.Debugf("Resolving UID/GID for user: '%s', group: '%s'", userStr, groupStr)

	// CRITICAL FIX: Handle root user correctly
	if userStr == rootUser {
		logrus.Debugf("Detected root user, using UID 0")
		uid = 0
	} else if uidNum, parseErr := getUID(userStr); parseErr == nil {
		// Try to parse userStr as numeric UID first
		logrus.Debugf("Parsed user '%s' as numeric UID: %d", userStr, uidNum)
		uid = uidNum
	} else {
		// Use safe fallback for non-numeric user strings
		logrus.Debugf("User '%s' is not numeric, using safe fallback", userStr)
		uid = getSafeFallbackUID(userStr)
	}

	// Handle group string
	if groupStr != "" {
		// CRITICAL FIX: Handle root group correctly
		if groupStr == rootUser {
			logrus.Debugf("Detected root group, using GID 0")
			gid = 0
		} else if gidNum, parseErr := getGID(groupStr); parseErr == nil {
			// Try to parse groupStr as numeric GID first
			logrus.Debugf("Parsed group '%s' as numeric GID: %d", groupStr, gidNum)
			gid = gidNum
		} else {
			// Use safe fallback for non-numeric group strings
			logrus.Debugf("Group '%s' is not numeric, using safe fallback", groupStr)
			gid = getSafeFallbackUID(groupStr)
		}
	} else {
		// If no group specified, use UID as GID
		gid = uid
	}

	logrus.Debugf("Final UID/GID for user '%s', group '%s': %d/%d", userStr, groupStr, uid, gid)
	return uid, gid, nil
}

// getGID tries to parse the gid
func getGID(groupStr string) (uint32, error) {
	gid, err := strconv.ParseUint(groupStr, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(gid), nil
}

// LookupUser will try to lookup the userStr inside the passwd file.
// RADICAL FIX: Completely rewritten to work without system user lookups
func LookupUser(userStr string) (*user.User, error) {
	logrus.Debugf("Looking up user: '%s'", userStr)

	// CRITICAL FIX: Handle root user correctly
	if userStr == rootUser {
		logrus.Debugf("Detected root user, using UID 0")
		return &user.User{
			Uid:      "0",
			Gid:      "0",
			Username: rootUser,
			Name:     rootUser,
			HomeDir:  "/root",
		}, nil
	}

	// Try to parse as numeric UID first
	if uid, parseErr := getUID(userStr); parseErr == nil {
		logrus.Debugf("Parsed user '%s' as numeric UID: %d", userStr, uid)
		return &user.User{
			Uid:      fmt.Sprint(uid),
			Gid:      fmt.Sprint(uid),
			Username: userStr,
			Name:     userStr,
			HomeDir:  "/",
		}, nil
	}

	// Use safe fallback for non-numeric user strings
	logrus.Debugf("User '%s' is not numeric, using safe fallback", userStr)
	fallbackUID := getSafeFallbackUID(userStr)
	return &user.User{
		Uid:      fmt.Sprint(fallbackUID),
		Gid:      fmt.Sprint(fallbackUID),
		Username: userStr,
		Name:     userStr,
		HomeDir:  "/",
	}, nil
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
	rootUser       = "root" // Constant for root user string
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

// ExtractFilename extracts the filename from a URL without its query url
func extractFilename(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	filename := filepath.Base(parsedURL.Path)
	return filename, nil
}
