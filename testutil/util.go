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

package testutil

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"
)

const (
	// defaultDirPerm is the default directory permissions (0o750)
	defaultDirPerm = 0o750
	// defaultFilePerm is the default file permissions (0o600)
	defaultFilePerm = 0o600
)

// SetupFiles creates files at path
func SetupFiles(path string, files map[string]string) error {
	for p, c := range files {
		fullPath := filepath.Join(path, p)
		if err := os.MkdirAll(filepath.Dir(fullPath), defaultDirPerm); err != nil {
			return err
		}
		if err := os.WriteFile(fullPath, []byte(c), defaultFilePerm); err != nil {
			return err
		}
	}
	return nil
}

// CurrentUser represents the current user with primary group information
type CurrentUser struct {
	*user.User

	PrimaryGroup string
}

// GetCurrentUser retrieves the current user with primary group information
func GetCurrentUser(t *testing.T) CurrentUser {
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("Cannot get current user: %s", err)
	}
	groups, err := currentUser.GroupIds()
	if err != nil || len(groups) == 0 {
		t.Fatalf("Cannot get groups for current user: %s", err)
	}
	primaryGroupObj, err := user.LookupGroupId(groups[0])
	if err != nil {
		t.Fatalf("Could not lookup name of group %s: %s", groups[0], err)
	}
	primaryGroup := primaryGroupObj.Name

	return CurrentUser{
		User:         currentUser,
		PrimaryGroup: primaryGroup,
	}
}

// CheckDeepEqual checks if two values are deeply equal using cmp.Diff
func CheckDeepEqual(t *testing.T, expected, actual interface{}) {
	t.Helper()
	if diff := cmp.Diff(actual, expected); diff != "" {
		t.Errorf("%T differ (-got, +want): %s", expected, diff)
		return
	}
}

// CheckErrorAndDeepEqual checks for expected errors and deep equality of values
func CheckErrorAndDeepEqual(t *testing.T, shouldErr bool, err error, expected, actual interface{}) {
	t.Helper()
	if checkErr := checkErr(shouldErr, err); checkErr != nil {
		t.Error(err)
		return
	}
	if !reflect.DeepEqual(expected, actual) {
		diff := cmp.Diff(actual, expected)
		t.Errorf("%T differ (-got, +want): %s", expected, diff)
		return
	}
}

// CheckError checks if the error condition matches expectations
func CheckError(t *testing.T, shouldErr bool, err error) {
	if checkErr := checkErr(shouldErr, err); checkErr != nil {
		t.Error(err)
	}
}

// CheckNoError verifies that no error occurred
func CheckNoError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("%+v", err)
	}
}

func checkErr(shouldErr bool, err error) error {
	if err == nil && shouldErr {
		return fmt.Errorf("expected error, but returned none")
	}
	if err != nil && !shouldErr {
		return fmt.Errorf("unexpected error: %w", err)
	}
	return nil
}
