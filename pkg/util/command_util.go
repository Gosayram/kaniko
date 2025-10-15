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

func IsSrcsValid(srcsAndDest instructions.SourcesAndDest, resolvedSources []string, fileContext FileContext) error {
	srcs := srcsAndDest.SourcePaths
	dest := srcsAndDest.DestPath

	if !ContainsWildcards(srcs) {
		totalSrcs := 0
		for _, src := range srcs {
			if fileContext.ExcludesFile(src) {
				continue
			}
			totalSrcs++
		}
		if totalSrcs > 1 && !IsDestDir(dest) {
			// Docker allows copying multiple sources to non-existent paths, creating a directory
			// We should only error if the destination is explicitly a file (exists and is not a directory)
			// But we need to check if the destination is explicitly marked as a directory with trailing slash
			if strings.HasSuffix(dest, "/") || dest == "." {
				// Destination is explicitly a directory, allow the copy
			} else if fi, err := os.Stat(dest); err == nil && !fi.IsDir() {
				// Destination exists and is a file, this is an error
				return errors.New("when specifying multiple sources in a COPY command, destination must be a directory and end in '/'")
			}
			// If destination doesn't exist, allow the copy (Docker behavior)
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
		// Don't return early for directories - let the totalFiles check handle it
		if fi.IsDir() {
			// Continue to totalFiles check below
		}
	}

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
	// ignore the case where whildcards and there are no files to copy
	if totalFiles == 0 {
		// using log warning instead of return errors.New("copy failed: no source files specified")
		logrus.Warn("No files to copy")
	}
	// If there are wildcards, and the destination is a file, there must be exactly one file to copy over,
	// Otherwise, return an error
	if !IsDestDir(dest) && totalFiles > 1 {
		// Docker allows copying multiple sources to non-existent paths, creating a directory
		// We should only error if the destination is explicitly a file (exists and is not a directory)
		// But we need to check if the destination is explicitly marked as a directory with trailing slash
		if strings.HasSuffix(dest, "/") || dest == "." {
			// Destination is explicitly a directory, allow the copy
		} else if fi, err := os.Stat(dest); err == nil && !fi.IsDir() {
			// Destination exists and is a file, this is an error
			return errors.New("when specifying multiple sources in a COPY command, destination must be a directory and end in '/'")
		}
		// If destination doesn't exist, allow the copy (Docker behavior)
	}
	return nil
}

// countEffectiveSources counts unique, non-excluded, existing sources from the resolvedSources list.
// Remote URLs are counted as sources. Files that do not exist (e.g. unmatched wildcards) are ignored.
func countEffectiveSources(resolvedSources []string, fileContext FileContext) (int, error) {
	counted := 0
	for _, src := range resolvedSources {
		if IsSrcRemoteFileURL(src) {
			counted++
			continue
		}

		// Normalize and strip the optional "context/" prefix because Root already points to the build context
		cleanSrc := filepath.Clean(src)
		cleanSrc = strings.TrimPrefix(cleanSrc, "context/")
		var absPath string
		if filepath.IsAbs(cleanSrc) {
			absPath = cleanSrc
		} else {
			absPath = filepath.Join(fileContext.Root, cleanSrc)
		}
		if fileContext.ExcludesFile(absPath) {
			continue
		}

		if _, err := os.Lstat(absPath); err != nil {
			// Ignore non-existing entries (e.g., unmatched wildcards)
			if os.IsNotExist(err) {
				continue
			}
			return 0, errors.Wrap(err, "stat source")
		}

		counted++
		if counted > 1 {
			// Early exit: we only need to know if there is more than one
			return counted, nil
		}
	}
	return counted, nil
}

// countEffectiveInputSources counts existing, non-excluded sources from the input source list.
// It ignores entries that do not exist. This is used only when no wildcards are present in inputs.
func countEffectiveInputSources(inputSrcs []string, fileContext FileContext) (int, error) {
	counted := 0
	for _, src := range inputSrcs {
		// Skip excluded
		if fileContext.ExcludesFile(src) {
			continue
		}

		// Determine absolute path if relative to build context
		abs := src
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(fileContext.Root, src)
		}
		if _, err := os.Lstat(abs); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return 0, errors.Wrap(err, "stat input source")
		}
		counted++
		if counted > 1 {
			return counted, nil
		}
	}
	return counted, nil
}

func validateNonWildcardSources(srcs []string, dest string, fileContext FileContext) error {
	if ContainsWildcards(srcs) {
		return nil
	}

	totalSrcs := 0
	for _, src := range srcs {
		if fileContext.ExcludesFile(src) {
			continue
		}
		totalSrcs++
	}
	if totalSrcs > 1 {
		// For multiple sources, we need to be more permissive to match Docker behavior
		// Docker allows copying multiple sources to non-existent paths, creating a directory
		// We should only error if the destination is explicitly a file (exists and is not a directory)
		// But we need to check if the destination is explicitly marked as a directory with trailing slash
		if strings.HasSuffix(dest, "/") || dest == "." {
			// Destination is explicitly a directory, allow the copy
		} else if fi, err := os.Stat(dest); err == nil && !fi.IsDir() {
			// Destination exists and is a file, this is an error
			return errors.New("when specifying multiple sources in a COPY command, " +
				"destination must be a directory and end in '/'")
		}
		// If destination doesn't exist, allow the copy (Docker behavior)
	}
	return nil
}

func checkSingleDirectorySource(resolvedSources []string, dest string, fileContext FileContext) error {
	if len(resolvedSources) != 1 {
		return nil
	}

	if IsSrcRemoteFileURL(resolvedSources[0]) {
		return nil
	}

	src := filepath.Clean(resolvedSources[0])
	src = strings.TrimPrefix(src, "context/")
	path := filepath.Join(fileContext.Root, src)
	fi, err := os.Lstat(path)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to get fileinfo for %v", path))
	}
	// If the single source is a directory (or explicitly ends with '/') and destination is not a directory, error.
	if fi.IsDir() || strings.HasSuffix(resolvedSources[0], pathSeparator) {
		// Docker allows copying a directory to a non-existent path, which creates a directory
		// We should only error if the destination is explicitly a file (exists and is not a directory)
		if IsDestDir(dest) {
			return nil
		}
		// Check if destination exists and is a file
		if fi, err := os.Stat(dest); err == nil && !fi.IsDir() {
			return errors.New("when copying a directory, destination must be a directory and end in '/'")
		}
		// If destination doesn't exist, allow the copy (Docker behavior)
	}
	return nil
}

func countTotalFiles(resolvedSources []string, fileContext FileContext) (int, error) {
	totalFiles := 0
	for _, src := range resolvedSources {
		if IsSrcRemoteFileURL(src) {
			totalFiles++
			continue
		}
		src = filepath.Clean(src)
		// Strip the "context/" prefix from src if it exists, since the fileContext.Root already includes it
		cleanSrc := strings.TrimPrefix(src, "context/")
		logrus.Debugf("countTotalFiles: src=%s, cleanSrc=%s, fileContext.Root=%s", src, cleanSrc, fileContext.Root)
		files, err := RelativeFiles(cleanSrc, fileContext.Root)
		if err != nil {
			return 0, errors.Wrap(err, "failed to get relative files")
		}
		for _, file := range files {
			if fileContext.ExcludesFile(file) {
				continue
			}
			totalFiles++
		}
	}

	// ignore the case where wildcards and there are no files to copy
	if totalFiles == 0 {
		logrus.Warn("No files to copy")
	}
	return totalFiles, nil
}

func validateDestinationForMultipleFiles(totalFiles int, dest string) error {
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
func GetUserGroup(chownStr string, env []string) (uid, gid int64, err error) {
	if chownStr == "" {
		return DoNotChangeUID, DoNotChangeGID, nil
	}

	chown, err := ResolveEnvironmentReplacement(chownStr, env, false)
	if err != nil {
		return -1, -1, err
	}

	uid32, gid32, err := getUIDAndGIDFromString(chown)
	if err != nil {
		return -1, -1, err
	}

	return int64(uid32), int64(gid32), nil
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
		return 0, 0, err
	}
	uid32, err := getUID(userObj.Uid)
	if err != nil {
		return 0, 0, err
	}

	if groupStr != "" {
		gid32, err := getGIDFromName(groupStr)
		if err != nil {
			if errors.Is(err, fallbackToUIDError) {
				return uid32, uid32, nil
			}
			return 0, 0, err
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
func getGIDFromName(groupStr string) (uint32, error) {
	group, err := user.LookupGroup(groupStr)
	if err != nil {
		// unknown group error could relate to a non existing group
		var groupErr user.UnknownGroupError
		if errors.As(err, &groupErr) {
			return getGID(groupStr)
		}
		group, err = user.LookupGroupId(groupStr)
		if err != nil {
			return getGID(groupStr)
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
				// at this point, the user does not exist and the userStr is not a valid number.
				return nil, fmt.Errorf("user %v is not a uid and does not exist on the system", userStr)
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

// ExtractFilename extracts the filename from a URL without its query url
func extractFilename(rawURL string) (string, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	filename := filepath.Base(parsedURL.Path)
	return filename, nil
}
