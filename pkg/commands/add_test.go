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

package commands

import (
	"compress/gzip"
	"os"
	"path/filepath"
	"sort"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"

	"github.com/Gosayram/kaniko/pkg/dockerfile"
	"github.com/Gosayram/kaniko/pkg/util"
	"github.com/Gosayram/kaniko/testutil"
)

type TarList struct {
	tarName    string
	directory  string
	compressed bool
}

func createFile(tempDir string) error {
	fileName := filepath.Join(tempDir, "text.txt")
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	err = os.WriteFile(fileName, []byte("This is a test!\n"), 0644)
	if err != nil {
		return err
	}
	return nil
}

func createTar(tempDir string, toCreate TarList) error {
	if toCreate.compressed {
		file, err := os.OpenFile(filepath.Join(tempDir, toCreate.tarName), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			return err
		}

		gzipWriter := gzip.NewWriter(file)
		defer gzipWriter.Close()

		err = util.CreateTarballOfDirectory(filepath.Join(tempDir, toCreate.directory), gzipWriter)
		if err != nil {
			return err
		}
		return nil
	}

	tarFile, err := os.Create(filepath.Join(tempDir, toCreate.tarName))
	if err != nil {
		return err
	}
	err = util.CreateTarballOfDirectory(filepath.Join(tempDir, toCreate.directory), tarFile)
	if err != nil {
		return err
	}

	return nil
}

func setupAddTest(t *testing.T) string {
	tempDir := t.TempDir()

	err := createFile(tempDir)
	if err != nil {
		t.Errorf("couldn't create the file %v", err)
	}

	var tarFiles = []TarList{
		{
			tarName:    "a.tar",
			directory:  "a",
			compressed: false,
		},
		{
			tarName:    "b.tar.gz",
			directory:  "b",
			compressed: true,
		},
	}

	// Create directories with files and then create tar
	for _, toCreate := range tarFiles {

		err = os.Mkdir(filepath.Join(tempDir, toCreate.directory), 0o755)
		if err != nil {
			t.Errorf("couldn't create directory %v", err)
		}

		err = createFile(filepath.Join(tempDir, toCreate.directory))
		if err != nil {
			t.Errorf("couldn't create file inside directory %v", err)
		}
		err = createTar(tempDir, toCreate)

		if err != nil {
			t.Errorf("couldn't create the tar %v", err)
		}
	}

	return tempDir
}

func Test_AddCommand(t *testing.T) {
	tempDir := setupAddTest(t)

	fileContext := util.FileContext{Root: tempDir}
	cfg := &v1.Config{
		Cmd:        nil,
		Env:        []string{},
		WorkingDir: tempDir,
	}
	buildArgs := dockerfile.NewBuildArgs([]string{})

	var addTests = []struct {
		name           string
		sourcesAndDest []string
		expectedDest   []string
	}{
		{
			name:           "add files into tempAddExecuteTest/",
			sourcesAndDest: []string{"text.txt", "a.tar", "b.tar.gz", "tempAddExecuteTest/"},
			expectedDest: []string{
				"text.txt",
				filepath.Join(tempDir, "a/"),
				filepath.Join(tempDir, "a/text.txt"),
				filepath.Join(tempDir, "b/"),
				filepath.Join(tempDir, "b/text.txt"),
			},
		},
	}

	for _, testCase := range addTests {
		t.Run(testCase.name, func(t *testing.T) {
			c := AddCommand{
				cmd: &instructions.AddCommand{
					SourcesAndDest: instructions.SourcesAndDest{SourcePaths: testCase.sourcesAndDest[0 : len(testCase.sourcesAndDest)-1],
						DestPath: testCase.sourcesAndDest[len(testCase.sourcesAndDest)-1]},
				},
				fileContext: fileContext,
			}
			c.ExecuteCommand(cfg, buildArgs)

			expected := []string{}
			resultDir := filepath.Join(tempDir, "tempAddExecuteTest/")
			for _, file := range testCase.expectedDest {
				expected = append(expected, filepath.Join(resultDir, file))
			}
			sort.Strings(expected)
			sort.Strings(c.snapshotFiles)
			testutil.CheckDeepEqual(t, expected, c.snapshotFiles)
		})
	}
}

// TestAddCommand_FilesUsedFromContext_NilBuildArgs tests that AddCommand.FilesUsedFromContext
// handles nil buildArgs gracefully without panicking
func TestAddCommand_FilesUsedFromContext_NilBuildArgs(t *testing.T) {
	tempDir := t.TempDir()

	// Create a test file
	testFile := filepath.Join(tempDir, "test.txt")
	err := os.WriteFile(testFile, []byte("test content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	fileContext := util.FileContext{Root: tempDir}
	cfg := &v1.Config{
		Env: []string{"PATH=/usr/bin"},
	}

	addCmd := AddCommand{
		cmd: &instructions.AddCommand{
			SourcesAndDest: instructions.SourcesAndDest{
				SourcePaths: []string{"test.txt"},
				DestPath:    "/app/",
			},
		},
		fileContext: fileContext,
	}

	// This should not panic even with nil buildArgs
	var nilBuildArgs *dockerfile.BuildArgs = nil
	files, err := addCmd.FilesUsedFromContext(cfg, nilBuildArgs)

	if err != nil {
		t.Errorf("FilesUsedFromContext should not return error with nil buildArgs, got: %v", err)
	}

	// Should return the file path
	expectedFile := filepath.Join(tempDir, "test.txt")
	if len(files) != 1 {
		t.Errorf("Expected 1 file, got %d: %v", len(files), files)
	} else if files[0] != expectedFile {
		t.Errorf("Expected file %s, got %s", expectedFile, files[0])
	}
}

// TestAddCommand_FilesUsedFromContext_WithBuildArgs tests that AddCommand.FilesUsedFromContext
// works correctly with buildArgs
func TestAddCommand_FilesUsedFromContext_WithBuildArgs(t *testing.T) {
	tempDir := t.TempDir()

	// Create a test file
	testFile := filepath.Join(tempDir, "test.txt")
	err := os.WriteFile(testFile, []byte("test content"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	fileContext := util.FileContext{Root: tempDir}
	cfg := &v1.Config{
		Env: []string{"PATH=/usr/bin"},
	}
	buildArgs := dockerfile.NewBuildArgs([]string{"PNPM_VERSION=10.12.3"})

	addCmd := AddCommand{
		cmd: &instructions.AddCommand{
			SourcesAndDest: instructions.SourcesAndDest{
				SourcePaths: []string{"test.txt"},
				DestPath:    "/app/",
			},
		},
		fileContext: fileContext,
	}

	files, err := addCmd.FilesUsedFromContext(cfg, buildArgs)

	if err != nil {
		t.Errorf("FilesUsedFromContext should not return error, got: %v", err)
	}

	expectedFile := filepath.Join(tempDir, "test.txt")
	if len(files) != 1 {
		t.Errorf("Expected 1 file, got %d: %v", len(files), files)
	} else if files[0] != expectedFile {
		t.Errorf("Expected file %s, got %s", expectedFile, files[0])
	}
}

// TestAddCommand_FilesUsedFromContext_RemoteURL tests that remote URLs are excluded
func TestAddCommand_FilesUsedFromContext_RemoteURL(t *testing.T) {
	tempDir := t.TempDir()
	fileContext := util.FileContext{Root: tempDir}
	cfg := &v1.Config{
		Env: []string{},
	}

	addCmd := AddCommand{
		cmd: &instructions.AddCommand{
			SourcesAndDest: instructions.SourcesAndDest{
				SourcePaths: []string{"https://example.com/file.txt"},
				DestPath:    "/app/",
			},
		},
		fileContext: fileContext,
	}

	// Should not panic with nil buildArgs
	files, err := addCmd.FilesUsedFromContext(cfg, nil)

	if err != nil {
		t.Errorf("FilesUsedFromContext should not return error, got: %v", err)
	}

	// Remote URLs should be excluded
	if len(files) != 0 {
		t.Errorf("Expected 0 files (remote URL excluded), got %d: %v", len(files), files)
	}
}

// TestAddCommand_FilesUsedFromContext_EmptyConfig tests edge case with empty config
func TestAddCommand_FilesUsedFromContext_EmptyConfig(t *testing.T) {
	tempDir := t.TempDir()

	testFile := filepath.Join(tempDir, "test.txt")
	err := os.WriteFile(testFile, []byte("test"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	fileContext := util.FileContext{Root: tempDir}
	cfg := &v1.Config{
		Env: []string{}, // Empty env
	}

	addCmd := AddCommand{
		cmd: &instructions.AddCommand{
			SourcesAndDest: instructions.SourcesAndDest{
				SourcePaths: []string{"test.txt"},
				DestPath:    "/app/",
			},
		},
		fileContext: fileContext,
	}

	// Should work with nil buildArgs and empty config
	files, err := addCmd.FilesUsedFromContext(cfg, nil)

	if err != nil {
		t.Errorf("FilesUsedFromContext should not return error, got: %v", err)
	}

	expectedFile := filepath.Join(tempDir, "test.txt")
	if len(files) != 1 || files[0] != expectedFile {
		t.Errorf("Expected [%s], got %v", expectedFile, files)
	}
}
