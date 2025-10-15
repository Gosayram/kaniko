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
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/constants"
	"github.com/Gosayram/kaniko/pkg/mocks/go-containerregistry/mockv1"
	"github.com/Gosayram/kaniko/testutil"
)

func Test_DetectFilesystemSkiplist(t *testing.T) {
	testDir := t.TempDir()
	fileContents := `
	228 122 0:90 / / rw,relatime - aufs none rw,si=f8e2406af90782bc,dio,dirperm1
	229 228 0:98 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
	230 228 0:99 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
	231 230 0:100 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=666
	232 228 0:101 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro`

	path := filepath.Join(testDir, "mountinfo")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("Error creating tempdir: %s", err)
	}
	if err := os.WriteFile(path, []byte(fileContents), 0o644); err != nil {
		t.Fatalf("Error writing file contents to %s: %s", path, err)
	}

	// Reset ignorelist to default before test
	originalIgnorelist := append([]IgnoreListEntry{}, ignorelist...)

	// Save original KanikoDir and set it to the expected value
	originalKanikoDir := config.KanikoDir
	config.KanikoDir = "/kaniko"
	defer func() {
		ignorelist = originalIgnorelist
		config.KanikoDir = originalKanikoDir
	}()

	err := DetectFilesystemIgnoreList(path)

	expectedSkiplist := []IgnoreListEntry{
		{"/kaniko", false},
		{"/proc", false},
		{"/dev", false},
		{"/dev/pts", false},
		{"/sys", false},
		{"/etc/mtab", false},
		{"/tmp/apt-key-gpghome", true},
	}
	actualSkiplist := ignorelist
	sort.Slice(actualSkiplist, func(i, j int) bool {
		return actualSkiplist[i].Path < actualSkiplist[j].Path
	})
	sort.Slice(expectedSkiplist, func(i, j int) bool {
		return expectedSkiplist[i].Path < expectedSkiplist[j].Path
	})
	testutil.CheckErrorAndDeepEqual(t, false, err, expectedSkiplist, actualSkiplist)
}

func Test_AddToIgnoreList(t *testing.T) {
	t.Cleanup(func() {
		ignorelist = append([]IgnoreListEntry{}, defaultIgnoreList...)
	})

	AddToIgnoreList(IgnoreListEntry{
		Path:            "/tmp",
		PrefixMatchOnly: false,
	})

	if !CheckIgnoreList("/tmp") {
		t.Errorf("CheckIgnoreList() = %v, want %v", false, true)
	}
}

var tests = []struct {
	files         map[string]string
	directory     string
	expectedFiles []string
}{
	{
		files: map[string]string{
			"/workspace/foo/a": "baz1",
			"/workspace/foo/b": "baz2",
			"/kaniko/file":     "file",
		},
		directory: "/workspace/foo/",
		expectedFiles: []string{
			"workspace/foo/a",
			"workspace/foo/b",
			"workspace/foo",
		},
	},
	{
		files: map[string]string{
			"/workspace/foo/a": "baz1",
		},
		directory: "/workspace/foo/a",
		expectedFiles: []string{
			"workspace/foo/a",
		},
	},
	{
		files: map[string]string{
			"/workspace/foo/a": "baz1",
			"/workspace/foo/b": "baz2",
			"/workspace/baz":   "hey",
			"/kaniko/file":     "file",
		},
		directory: "/workspace",
		expectedFiles: []string{
			"workspace/foo/a",
			"workspace/foo/b",
			"workspace/baz",
			"workspace",
			"workspace/foo",
		},
	},
	{
		files: map[string]string{
			"/workspace/foo/a": "baz1",
			"/workspace/foo/b": "baz2",
		},
		directory: "",
		expectedFiles: []string{
			"workspace/foo/a",
			"workspace/foo/b",
			"workspace",
			"workspace/foo",
			".",
		},
	},
}

func Test_RelativeFiles(t *testing.T) {
	for _, test := range tests {
		testDir := t.TempDir()
		if err := testutil.SetupFiles(testDir, test.files); err != nil {
			t.Fatalf("err setting up files: %v", err)
		}
		actualFiles, err := RelativeFiles(test.directory, testDir)
		sort.Strings(actualFiles)
		sort.Strings(test.expectedFiles)
		testutil.CheckErrorAndDeepEqual(t, false, err, test.expectedFiles, actualFiles)
	}
}

func Test_ParentDirectories(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		rootDir  string
		expected []string
	}{
		{
			name:    "regular path",
			path:    "/path/to/dir",
			rootDir: "/",
			expected: []string{
				"/",
				"/path",
				"/path/to",
			},
		},
		{
			name:    "current directory",
			path:    ".",
			rootDir: "/",
			expected: []string{
				"/",
			},
		},
		{
			name:    "non / root directory",
			path:    "/tmp/kaniko/test/another/dir",
			rootDir: "/tmp/kaniko/",
			expected: []string{
				"/tmp/kaniko",
				"/tmp/kaniko/test",
				"/tmp/kaniko/test/another",
			},
		},
		{
			name:    "non / root director same path",
			path:    "/tmp/123",
			rootDir: "/tmp/123",
			expected: []string{
				"/tmp/123",
			},
		},
		{
			name:    "non / root directory path",
			path:    "/tmp/120162240/kaniko",
			rootDir: "/tmp/120162240",
			expected: []string{
				"/tmp/120162240",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := config.RootDir
			defer func() { config.RootDir = original }()
			config.RootDir = tt.rootDir
			actual := ParentDirectories(tt.path)

			testutil.CheckErrorAndDeepEqual(t, false, nil, tt.expected, actual)
		})
	}
}

func Test_ParentDirectoriesWithoutLeadingSlash(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected []string
	}{
		{
			name: "regular path",
			path: "/path/to/dir",
			expected: []string{
				"",
				"path",
				"path/to",
			},
		},
		{
			name: "current directory",
			path: ".",
			expected: []string{
				"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := ParentDirectoriesWithoutLeadingSlash(tt.path)
			testutil.CheckErrorAndDeepEqual(t, false, nil, tt.expected, actual)
		})
	}
}

func Test_CheckIgnoreList(t *testing.T) {
	type args struct {
		path       string
		ignorelist []IgnoreListEntry
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "file ignored",
			args: args{
				path:       "/foo",
				ignorelist: []IgnoreListEntry{{"/foo", false}},
			},
			want: true,
		},
		{
			name: "directory ignored",
			args: args{
				path:       "/foo/bar",
				ignorelist: []IgnoreListEntry{{"/foo", false}},
			},
			want: true,
		},
		{
			name: "grandparent ignored",
			args: args{
				path:       "/foo/bar/baz",
				ignorelist: []IgnoreListEntry{{"/foo", false}},
			},
			want: true,
		},
		{
			name: "sibling ignored",
			args: args{
				path:       "/foo/bar/baz",
				ignorelist: []IgnoreListEntry{{"/foo/bat", false}},
			},
			want: false,
		},
		{
			name: "prefix match only ",
			args: args{
				path:       "/tmp/apt-key-gpghome.xft/gpg.key",
				ignorelist: []IgnoreListEntry{{"/tmp/apt-key-gpghome.*", true}},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := ignorelist
			defer func() {
				ignorelist = original
			}()
			ignorelist = tt.args.ignorelist
			got := CheckIgnoreList(tt.args.path)
			if got != tt.want {
				t.Errorf("CheckIgnoreList() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasFilepathPrefix(t *testing.T) {
	type args struct {
		path            string
		prefix          string
		prefixMatchOnly bool
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "parent",
			args: args{
				path:            "/foo/bar",
				prefix:          "/foo",
				prefixMatchOnly: false,
			},
			want: true,
		},
		{
			name: "nested parent",
			args: args{
				path:            "/foo/bar/baz",
				prefix:          "/foo/bar",
				prefixMatchOnly: false,
			},
			want: true,
		},
		{
			name: "sibling",
			args: args{
				path:            "/foo/bar",
				prefix:          "/bar",
				prefixMatchOnly: false,
			},
			want: false,
		},
		{
			name: "nested sibling",
			args: args{
				path:            "/foo/bar/baz",
				prefix:          "/foo/bar",
				prefixMatchOnly: false,
			},
			want: true,
		},
		{
			name: "name prefix",
			args: args{
				path:            "/foo2/bar",
				prefix:          "/foo",
				prefixMatchOnly: false,
			},
			want: false,
		},
		{
			name: "prefix match only (volume)",
			args: args{
				path:            "/foo",
				prefix:          "/foo",
				prefixMatchOnly: true,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasFilepathPrefix(tt.args.path, tt.args.prefix, tt.args.prefixMatchOnly); got != tt.want {
				t.Errorf("HasFilepathPrefix() = %v, want %v", got, tt.want)
			}
		})
	}
}

func BenchmarkHasFilepathPrefix(b *testing.B) {
	tests := []struct {
		path            string
		prefix          string
		prefixMatchOnly bool
	}{
		{
			path:            "/foo/bar",
			prefix:          "/foo",
			prefixMatchOnly: true,
		},
		{
			path:            "/foo/bar/baz",
			prefix:          "/foo",
			prefixMatchOnly: true,
		},
		{
			path:            "/foo/bar/baz/foo",
			prefix:          "/foo",
			prefixMatchOnly: true,
		},
		{
			path:            "/foo/bar/baz/foo/foobar",
			prefix:          "/foo",
			prefixMatchOnly: true,
		},
		{
			path:            "/foo/bar",
			prefix:          "/foo/bar",
			prefixMatchOnly: true,
		},
		{
			path:            "/foo/bar/baz",
			prefix:          "/foo/bar",
			prefixMatchOnly: true,
		},
		{
			path:            "/foo/bar/baz/foo",
			prefix:          "/foo/bar",
			prefixMatchOnly: true,
		},
		{
			path:            "/foo/bar/baz/foo/foobar",
			prefix:          "/foo/bar",
			prefixMatchOnly: true,
		},
		{
			path:            "/foo/bar",
			prefix:          "/foo/bar/baz",
			prefixMatchOnly: true,
		},
		{
			path:            "/foo/bar/baz",
			prefix:          "/foo/bar/baz",
			prefixMatchOnly: true,
		},
		{
			path:            "/foo/bar/baz/foo",
			prefix:          "/foo/bar/baz",
			prefixMatchOnly: true,
		},
		{
			path:            "/foo/bar/baz/foo/foobar",
			prefix:          "/foo/bar/baz",
			prefixMatchOnly: true,
		},
	}
	for _, ts := range tests {
		name := fmt.Sprint("PathDepth=", strings.Count(ts.path, "/"), ",PrefixDepth=", strings.Count(ts.prefix, "/"))
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				HasFilepathPrefix(ts.path, ts.prefix, ts.prefixMatchOnly)
			}
		})
	}
}

type checker func(root string, t *testing.T)

func fileExists(p string) checker {
	return func(root string, t *testing.T) {
		_, err := os.Stat(filepath.Join(root, p))
		if err != nil {
			t.Fatalf("File %s does not exist", filepath.Join(root, p))
		}
	}
}

func fileMatches(p string, c []byte) checker {
	return func(root string, t *testing.T) {
		actual, err := os.ReadFile(filepath.Join(root, p))
		if err != nil {
			t.Fatalf("error reading file: %s", p)
		}
		if !reflect.DeepEqual(actual, c) {
			t.Errorf("file contents do not match. %v!=%v", actual, c)
		}
	}
}

func timesMatch(p string, fTime time.Time) checker {
	return func(root string, t *testing.T) {
		fi, err := os.Stat(filepath.Join(root, p))
		if err != nil {
			t.Fatalf("error statting file %s", p)
		}

		if fi.ModTime().UTC() != fTime.UTC() {
			t.Errorf("Expected modtime to equal %v but was %v", fTime, fi.ModTime())
		}
	}
}

func permissionsMatch(p string, perms os.FileMode) checker {
	return func(root string, t *testing.T) {
		fi, err := os.Stat(filepath.Join(root, p))
		if err != nil {
			t.Fatalf("error statting file %s", p)
		}
		if fi.Mode() != perms {
			t.Errorf("Permissions do not match. %s != %s", fi.Mode(), perms)
		}
	}
}

func linkPointsTo(src, dst string) checker {
	return func(root string, t *testing.T) {
		link := filepath.Join(root, src)
		got, err := os.Readlink(link)
		if err != nil {
			t.Fatalf("error reading link %s: %s", link, err)
		}
		if got != dst {
			t.Errorf("link destination does not match: %s != %s", got, dst)
		}
	}
}

func filesAreHardlinks(first, second string) checker {
	return func(root string, t *testing.T) {
		fi1, err := os.Stat(filepath.Join(root, first))
		if err != nil {
			t.Fatalf("error getting file %s", first)
		}
		fi2, err := os.Stat(filepath.Join(root, second))
		if err != nil {
			t.Fatalf("error getting file %s", second)
		}
		stat1 := getSyscallStatT(fi1)
		stat2 := getSyscallStatT(fi2)
		if stat1.Ino != stat2.Ino {
			t.Errorf("%s and %s aren't hardlinks as they dont' have the same inode", first, second)
		}
	}
}

func fileHeader(name string, contents string, mode int64, fTime time.Time) *tar.Header {
	return &tar.Header{
		Name:       name,
		Size:       int64(len(contents)),
		Mode:       mode,
		Typeflag:   tar.TypeReg,
		Uid:        os.Getuid(),
		Gid:        os.Getgid(),
		AccessTime: fTime,
		ModTime:    fTime,
	}
}

func linkHeader(name, linkname string) *tar.Header {
	return &tar.Header{
		Name:     name,
		Size:     0,
		Typeflag: tar.TypeSymlink,
		Linkname: linkname,
	}
}

func hardlinkHeader(name, linkname string) *tar.Header {
	return &tar.Header{
		Name:     name,
		Size:     0,
		Typeflag: tar.TypeLink,
		Linkname: linkname,
	}
}

func dirHeader(name string, mode int64) *tar.Header {
	return &tar.Header{
		Name:     name,
		Size:     0,
		Typeflag: tar.TypeDir,
		Mode:     mode,
		Uid:      os.Getuid(),
		Gid:      os.Getgid(),
	}
}

func createUncompressedTar(fileContents map[string]string, tarFileName, testDir string) error {
	if err := testutil.SetupFiles(testDir, fileContents); err != nil {
		return err
	}
	tarFile, err := os.Create(filepath.Join(testDir, tarFileName))
	if err != nil {
		return err
	}
	t := NewTar(tarFile)
	defer t.Close()
	for file := range fileContents {
		filePath := filepath.Join(testDir, file)
		if err := t.AddFileToTar(filePath); err != nil {
			return err
		}
	}
	return nil
}

func Test_UnTar(t *testing.T) {
	testDir := t.TempDir()
	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)
	hdr := &tar.Header{
		Name:     "testfile",
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     11,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("hello world")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	files, err := UnTar(buf, testDir)
	testutil.CheckErrorAndDeepEqual(t, false, err, []string{filepath.Join(testDir, "testfile")}, files)

	// Make sure testdir still exists.
	_, err = os.Lstat(testDir)
	if err != nil {
		t.Errorf("expected testdir to exist, but could not Lstat it: %v", err)
	}
}

func TestExtractFile(t *testing.T) {
	type tc struct {
		name     string
		hdrs     []*tar.Header
		tmpdir   string
		contents []byte
		checkers []checker
	}

	defaultTestTime, err := time.Parse(time.RFC3339, "1912-06-23T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}

	tcs := []tc{
		{
			name:     "normal file",
			contents: []byte("helloworld"),
			hdrs:     []*tar.Header{fileHeader("./bar", "helloworld", 0o644, defaultTestTime)},
			checkers: []checker{
				fileExists("/bar"),
				fileMatches("/bar", []byte("helloworld")),
				permissionsMatch("/bar", 0o644),
				timesMatch("/bar", defaultTestTime),
			},
		},
		{
			name:     "normal file, directory does not exist",
			contents: []byte("helloworld"),
			hdrs:     []*tar.Header{fileHeader("./foo/bar", "helloworld", 0o644, defaultTestTime)},
			checkers: []checker{
				fileExists("/foo/bar"),
				fileMatches("/foo/bar", []byte("helloworld")),
				permissionsMatch("/foo/bar", 0o644),
				permissionsMatch("/foo", 0o755|os.ModeDir),
			},
		},
		{
			name:     "normal file, directory is created after",
			contents: []byte("helloworld"),
			hdrs: []*tar.Header{
				fileHeader("./foo/bar", "helloworld", 0o644, defaultTestTime),
				dirHeader("./foo", 0o722),
			},
			checkers: []checker{
				fileExists("/foo/bar"),
				fileMatches("/foo/bar", []byte("helloworld")),
				permissionsMatch("/foo/bar", 0o644),
				permissionsMatch("/foo", 0o722|os.ModeDir),
			},
		},
		{
			name: "symlink",
			hdrs: []*tar.Header{linkHeader("./bar", "bar/bat")},
			checkers: []checker{
				linkPointsTo("/bar", "bar/bat"),
			},
		},
		{
			name: "symlink relative path",
			hdrs: []*tar.Header{linkHeader("./bar", "./foo/bar/baz")},
			checkers: []checker{
				linkPointsTo("/bar", "./foo/bar/baz"),
			},
		},
		{
			name: "symlink parent does not exist",
			hdrs: []*tar.Header{linkHeader("./foo/bar/baz", "../../bat")},
			checkers: []checker{
				linkPointsTo("/foo/bar/baz", "../../bat"),
			},
		},
		{
			name: "symlink parent does not exist 2",
			hdrs: []*tar.Header{linkHeader("./foo/bar/baz", "../../bat")},
			checkers: []checker{
				linkPointsTo("/foo/bar/baz", "../../bat"),
				permissionsMatch("/foo", 0o755|os.ModeDir),
				permissionsMatch("/foo/bar", 0o755|os.ModeDir),
			},
		},
		{
			name:   "hardlink",
			tmpdir: "/tmp/hardlink",
			hdrs: []*tar.Header{
				fileHeader("/bin/gzip", "gzip-binary", 0o751, defaultTestTime),
				hardlinkHeader("/bin/uncompress", "/bin/gzip"),
			},
			checkers: []checker{
				fileExists("/bin/gzip"),
				filesAreHardlinks("/bin/uncompress", "/bin/gzip"),
			},
		},
		{
			name:     "file with setuid bit",
			contents: []byte("helloworld"),
			hdrs:     []*tar.Header{fileHeader("./bar", "helloworld", 0o4644, defaultTestTime)},
			checkers: []checker{
				fileExists("/bar"),
				fileMatches("/bar", []byte("helloworld")),
				permissionsMatch("/bar", 0o644|os.ModeSetuid),
			},
		},
		{
			name:     "dir with sticky bit",
			contents: []byte("helloworld"),
			hdrs: []*tar.Header{
				dirHeader("./foo", 0o1755),
				fileHeader("./foo/bar", "helloworld", 0o644, defaultTestTime),
			},
			checkers: []checker{
				fileExists("/foo/bar"),
				fileMatches("/foo/bar", []byte("helloworld")),
				permissionsMatch("/foo/bar", 0o644),
				permissionsMatch("/foo", 0o755|os.ModeDir|os.ModeSticky),
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tc := tc
			t.Parallel()
			r := ""

			if tc.tmpdir != "" {
				r = tc.tmpdir
			} else {
				r = t.TempDir()
			}
			defer os.RemoveAll(r)

			for _, hdr := range tc.hdrs {
				if err := ExtractFile(r, hdr, filepath.Clean(hdr.Name), bytes.NewReader(tc.contents)); err != nil {
					t.Fatal(err)
				}
			}
			for _, checker := range tc.checkers {
				checker(r, t)
			}
		})
	}
}

func TestCopySymlink(t *testing.T) {
	type tc struct {
		name       string
		linkTarget string
		dest       string
		beforeLink func(r string) error
	}

	tcs := []tc{{
		name:       "absolute symlink",
		linkTarget: "/abs/dest",
	}, {
		name:       "relative symlink",
		linkTarget: "rel",
	}, {
		name:       "symlink copy overwrites existing file",
		linkTarget: "/abs/dest",
		dest:       "overwrite_me",
		beforeLink: func(r string) error {
			return os.WriteFile(filepath.Join(r, "overwrite_me"), nil, 0o644)
		},
	}}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tc := tc
			t.Parallel()
			r := t.TempDir()
			os.MkdirAll(filepath.Join(r, filepath.Dir(tc.linkTarget)), 0o777)
			tc.linkTarget = filepath.Join(r, tc.linkTarget)
			os.WriteFile(tc.linkTarget, nil, 0o644)

			if tc.beforeLink != nil {
				if err := tc.beforeLink(r); err != nil {
					t.Fatal(err)
				}
			}
			link := filepath.Join(r, "link")
			dest := filepath.Join(r, "copy")
			if tc.dest != "" {
				dest = filepath.Join(r, tc.dest)
			}
			if err := os.Symlink(tc.linkTarget, link); err != nil {
				t.Fatal(err)
			}
			if _, err := CopySymlink(link, dest, FileContext{}); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(dest); err != nil {
				t.Fatalf("error reading link %s: %s", link, err)
			}
		})
	}
}

func Test_childDirInSkiplist(t *testing.T) {
	type args struct {
		path       string
		ignorelist []IgnoreListEntry
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "not in ignorelist",
			args: args{
				path: "/foo",
			},
			want: false,
		},
		{
			name: "child in ignorelist",
			args: args{
				path: "/foo",
				ignorelist: []IgnoreListEntry{
					{
						Path: "/foo/bar",
					},
				},
			},
			want: true,
		},
	}
	oldIgnoreList := ignorelist
	defer func() {
		ignorelist = oldIgnoreList
	}()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ignorelist = tt.args.ignorelist
			if got := childDirInIgnoreList(tt.args.path); got != tt.want {
				t.Errorf("childDirInIgnoreList() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_correctDockerignoreFileIsUsed(t *testing.T) {
	type args struct {
		dockerfilepath string
		buildcontext   string
		excluded       []string
		included       []string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "relative dockerfile used",
			args: args{
				dockerfilepath: "../../integration/dockerfiles/Dockerfile_dockerignore_relative",
				buildcontext:   "../../integration/",
				excluded:       []string{"ignore_relative/bar"},
				included:       []string{"ignore_relative/foo", "ignore/bar"},
			},
		},
		{
			name: "context dockerfile is used",
			args: args{
				dockerfilepath: "../../integration/dockerfiles/Dockerfile_test_dockerignore",
				buildcontext:   "../../integration/",
				excluded:       []string{"ignore/bar"},
				included:       []string{"ignore/foo", "ignore_relative/bar"},
			},
		},
	}
	for _, tt := range tests {
		fileContext, err := NewFileContextFromDockerfile(tt.args.dockerfilepath, tt.args.buildcontext)
		if err != nil {
			t.Fatal(err)
		}
		for _, excl := range tt.args.excluded {
			t.Run(tt.name+" to exclude "+excl, func(t *testing.T) {
				if !fileContext.ExcludesFile(excl) {
					t.Errorf("'%v' not excluded", excl)
				}
			})
		}
		for _, incl := range tt.args.included {
			t.Run(tt.name+" to include "+incl, func(t *testing.T) {
				if fileContext.ExcludesFile(incl) {
					t.Errorf("'%v' not included", incl)
				}
			})
		}
	}
}

func Test_CopyFile_skips_self(t *testing.T) {
	t.Parallel()
	tempDir := t.TempDir()

	tempFile := filepath.Join(tempDir, "foo")
	expected := "bar"

	if err := os.WriteFile(
		tempFile,
		[]byte(expected),
		0o755,
	); err != nil {
		t.Fatal(err)
	}

	ignored, err := CopyFile(tempFile, tempFile, FileContext{}, DoNotChangeUID, DoNotChangeGID, fs.FileMode(0o600), true)
	if err != nil {
		t.Fatal(err)
	}

	if ignored {
		t.Fatal("expected file to NOT be ignored")
	}

	// Ensure file has expected contents
	actualData, err := os.ReadFile(tempFile)
	if err != nil {
		t.Fatal(err)
	}

	if actual := string(actualData); actual != expected {
		t.Fatalf("expected file contents to be %q, but got %q", expected, actual)
	}
}

func fakeExtract(_ string, _ *tar.Header, _ string, _ io.Reader) error {
	return nil
}

func Test_GetFSFromLayers_with_whiteouts_include_whiteout_enabled(t *testing.T) {
	resetMountInfoFile := provideEmptyMountinfoFile()
	defer resetMountInfoFile()

	ctrl := gomock.NewController(t)

	root := t.TempDir()
	// Write a whiteout path
	d1 := []byte("Hello World\n")
	if err := os.WriteFile(filepath.Join(root, "foobar"), d1, 0o644); err != nil {
		t.Fatal(err)
	}

	opts := []FSOpt{
		// I'd rather use the real func (util.ExtractFile)
		// but you have to be root to chown
		ExtractFunc(fakeExtract),
		IncludeWhiteout(),
	}

	expectErr := false

	f := func(expectedFiles []string, tw *tar.Writer) {
		for _, f := range expectedFiles {
			f := strings.TrimPrefix(strings.TrimPrefix(f, root), "/")

			hdr := &tar.Header{
				Name: f,
				Mode: 0o644,
				Size: int64(len("Hello World\n")),
			}

			if err := tw.WriteHeader(hdr); err != nil {
				t.Fatal(err)
			}

			if _, err := tw.Write([]byte("Hello World\n")); err != nil {
				t.Fatal(err)
			}
		}

		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
	}

	expectedFiles := []string{
		filepath.Join(root, "foobar"),
	}

	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)

	f(expectedFiles, tw)

	mockLayer := mockv1.NewMockLayer(ctrl)
	mockLayer.EXPECT().MediaType().Return(types.OCILayer, nil)

	rc := io.NopCloser(buf)
	mockLayer.EXPECT().Uncompressed().Return(rc, nil)

	secondLayerFiles := []string{
		filepath.Join(root, ".wh.foobar"),
	}

	buf = new(bytes.Buffer)
	tw = tar.NewWriter(buf)

	f(secondLayerFiles, tw)

	mockLayer2 := mockv1.NewMockLayer(ctrl)
	mockLayer2.EXPECT().MediaType().Return(types.OCILayer, nil)

	rc = io.NopCloser(buf)
	mockLayer2.EXPECT().Uncompressed().Return(rc, nil)

	layers := []v1.Layer{
		mockLayer,
		mockLayer2,
	}

	expectedFiles = append(expectedFiles, secondLayerFiles...)

	actualFiles, err := GetFSFromLayers(root, layers, opts...)

	assertGetFSFromLayers(
		t,
		actualFiles,
		expectedFiles,
		err,
		expectErr,
	)
	// Make sure whiteout files are removed form the root.
	_, err = os.Lstat(filepath.Join(root, "foobar"))
	if err == nil || !os.IsNotExist(err) {
		t.Errorf("expected whiteout foobar file to be deleted. However found it.")
	}
}

func provideEmptyMountinfoFile() func() {
	// Provide empty mountinfo file to prevent /tmp from ending up in ignore list on
	// distributions with /tmp mountpoint. Otherwise, tests expecting operations in /tmp
	// can fail.
	config.MountInfoPath = "/dev/null"
	return func() {
		config.MountInfoPath = constants.MountInfoPath
	}
}

func Test_GetFSFromLayers_with_whiteouts_include_whiteout_disabled(t *testing.T) {
	resetMountInfoFile := provideEmptyMountinfoFile()
	defer resetMountInfoFile()

	ctrl := gomock.NewController(t)

	root := t.TempDir()
	// Write a whiteout path
	d1 := []byte("Hello World\n")
	if err := os.WriteFile(filepath.Join(root, "foobar"), d1, 0o644); err != nil {
		t.Fatal(err)
	}

	opts := []FSOpt{
		// I'd rather use the real func (util.ExtractFile)
		// but you have to be root to chown
		ExtractFunc(fakeExtract),
	}

	expectErr := false

	f := func(expectedFiles []string, tw *tar.Writer) {
		for _, f := range expectedFiles {
			f := strings.TrimPrefix(strings.TrimPrefix(f, root), "/")

			hdr := &tar.Header{
				Name: f,
				Mode: 0o644,
				Size: int64(len("Hello world\n")),
			}

			if err := tw.WriteHeader(hdr); err != nil {
				t.Fatal(err)
			}

			if _, err := tw.Write([]byte("Hello world\n")); err != nil {
				t.Fatal(err)
			}
		}

		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
	}

	expectedFiles := []string{
		filepath.Join(root, "foobar"),
	}

	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)

	f(expectedFiles, tw)

	mockLayer := mockv1.NewMockLayer(ctrl)
	mockLayer.EXPECT().MediaType().Return(types.OCILayer, nil)
	layerFiles := []string{
		filepath.Join(root, "foobar"),
	}
	buf = new(bytes.Buffer)
	tw = tar.NewWriter(buf)

	f(layerFiles, tw)

	rc := io.NopCloser(buf)
	mockLayer.EXPECT().Uncompressed().Return(rc, nil)

	secondLayerFiles := []string{
		filepath.Join(root, ".wh.foobar"),
	}

	buf = new(bytes.Buffer)
	tw = tar.NewWriter(buf)

	f(secondLayerFiles, tw)

	mockLayer2 := mockv1.NewMockLayer(ctrl)
	mockLayer2.EXPECT().MediaType().Return(types.OCILayer, nil)

	rc = io.NopCloser(buf)
	mockLayer2.EXPECT().Uncompressed().Return(rc, nil)

	layers := []v1.Layer{
		mockLayer,
		mockLayer2,
	}

	actualFiles, err := GetFSFromLayers(root, layers, opts...)

	assertGetFSFromLayers(
		t,
		actualFiles,
		expectedFiles,
		err,
		expectErr,
	)
	// Make sure whiteout files are removed form the root.
	_, err = os.Lstat(filepath.Join(root, "foobar"))
	if err == nil || !os.IsNotExist(err) {
		t.Errorf("expected whiteout foobar file to be deleted. However found it.")
	}
}

func Test_GetFSFromLayers_ignorelist(t *testing.T) {
	resetMountInfoFile := provideEmptyMountinfoFile()
	defer resetMountInfoFile()

	ctrl := gomock.NewController(t)

	root := t.TempDir()
	// Write a whiteout path
	fileContents := []byte("Hello World\n")
	if err := os.Mkdir(filepath.Join(root, "testdir"), 0o775); err != nil {
		t.Fatal(err)
	}

	opts := []FSOpt{
		// I'd rather use the real func (util.ExtractFile)
		// but you have to be root to chown
		ExtractFunc(fakeExtract),
		IncludeWhiteout(),
	}

	f := func(expectedFiles []string, tw *tar.Writer) {
		for _, f := range expectedFiles {
			f := strings.TrimPrefix(strings.TrimPrefix(f, root), "/")

			hdr := &tar.Header{
				Name: f,
				Mode: 0o644,
				Size: int64(len(string(fileContents))),
			}

			if err := tw.WriteHeader(hdr); err != nil {
				t.Fatal(err)
			}

			if _, err := tw.Write(fileContents); err != nil {
				t.Fatal(err)
			}
		}

		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
	}

	// first, testdir is not in ignorelist, so it should be deleted
	expectedFiles := []string{
		filepath.Join(root, ".wh.testdir"),
		filepath.Join(root, "testdir", "file"),
		filepath.Join(root, "other-file"),
	}

	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)

	f(expectedFiles, tw)

	mockLayer := mockv1.NewMockLayer(ctrl)
	mockLayer.EXPECT().MediaType().Return(types.OCILayer, nil)
	layerFiles := []string{
		filepath.Join(root, ".wh.testdir"),
		filepath.Join(root, "testdir", "file"),
		filepath.Join(root, "other-file"),
	}
	buf = new(bytes.Buffer)
	tw = tar.NewWriter(buf)

	f(layerFiles, tw)

	rc := io.NopCloser(buf)
	mockLayer.EXPECT().Uncompressed().Return(rc, nil)

	layers := []v1.Layer{
		mockLayer,
	}

	actualFiles, err := GetFSFromLayers(root, layers, opts...)
	assertGetFSFromLayers(
		t,
		actualFiles,
		expectedFiles,
		err,
		false,
	)

	// Make sure whiteout files are removed form the root.
	_, err = os.Lstat(filepath.Join(root, "testdir"))
	if err == nil || !os.IsNotExist(err) {
		t.Errorf("expected testdir to be deleted. However found it.")
	}

	// second, testdir is in ignorelist, so it should not be deleted
	original := append([]IgnoreListEntry{}, defaultIgnoreList...)
	defer func() {
		defaultIgnoreList = original
	}()
	defaultIgnoreList = append(defaultIgnoreList, IgnoreListEntry{
		Path: filepath.Join(root, "testdir"),
	})
	if err := os.Mkdir(filepath.Join(root, "testdir"), 0o775); err != nil {
		t.Fatal(err)
	}

	expectedFiles = []string{
		filepath.Join(root, "other-file"),
	}

	buf = new(bytes.Buffer)
	tw = tar.NewWriter(buf)

	f(expectedFiles, tw)

	mockLayer = mockv1.NewMockLayer(ctrl)
	mockLayer.EXPECT().MediaType().Return(types.OCILayer, nil)
	layerFiles = []string{
		filepath.Join(root, ".wh.testdir"),
		filepath.Join(root, "other-file"),
	}
	buf = new(bytes.Buffer)
	tw = tar.NewWriter(buf)

	f(layerFiles, tw)

	rc = io.NopCloser(buf)
	mockLayer.EXPECT().Uncompressed().Return(rc, nil)

	layers = []v1.Layer{
		mockLayer,
	}

	actualFiles, err = GetFSFromLayers(root, layers, opts...)
	assertGetFSFromLayers(
		t,
		actualFiles,
		expectedFiles,
		err,
		false,
	)

	// Make sure testdir still exists.
	_, err = os.Lstat(filepath.Join(root, "testdir"))
	if err != nil {
		t.Errorf("expected testdir to exist, but could not Lstat it: %v", err)
	}
}

func Test_GetFSFromLayers(t *testing.T) {
	ctrl := gomock.NewController(t)

	// Ensure mountinfo doesn't depend on host filesystem path
	resetMountInfoFile := provideEmptyMountinfoFile()
	defer resetMountInfoFile()

	root := t.TempDir()

	opts := []FSOpt{
		// I'd rather use the real func (util.ExtractFile)
		// but you have to be root to chown
		ExtractFunc(fakeExtract),
	}

	expectErr := false
	expectedFiles := []string{
		filepath.Join(root, "foobar"),
	}

	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)

	for _, f := range expectedFiles {
		f := strings.TrimPrefix(strings.TrimPrefix(f, root), "/")

		hdr := &tar.Header{
			Name: f,
			Mode: 0o644,
			Size: int64(len("Hello world\n")),
		}

		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}

		if _, err := tw.Write([]byte("Hello world\n")); err != nil {
			t.Fatal(err)
		}
	}

	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	mockLayer := mockv1.NewMockLayer(ctrl)
	mockLayer.EXPECT().MediaType().Return(types.OCILayer, nil)

	rc := io.NopCloser(buf)
	mockLayer.EXPECT().Uncompressed().Return(rc, nil)

	layers := []v1.Layer{
		mockLayer,
	}

	actualFiles, err := GetFSFromLayers(root, layers, opts...)

	assertGetFSFromLayers(
		t,
		actualFiles,
		expectedFiles,
		err,
		expectErr,
	)
}

func assertGetFSFromLayers(
	t *testing.T,
	actualFiles []string,
	expectedFiles []string,
	err error,
	expectErr bool, //nolint:unparam
) {
	t.Helper()
	if !expectErr && err != nil {
		t.Error(err)
		t.FailNow()
	} else if expectErr && err == nil {
		t.Error("expected err to not be nil")
		t.FailNow()
	}

	if len(actualFiles) != len(expectedFiles) {
		t.Errorf("expected %s to equal %s", actualFiles, expectedFiles)
		t.FailNow()
	}

	for i := range expectedFiles {
		if actualFiles[i] != expectedFiles[i] {
			t.Errorf("expected %s to equal %s", actualFiles[i], expectedFiles[i])
		}
	}
}

func TestInitIgnoreList(t *testing.T) {
	mountInfo := `36 35 98:0 /kaniko /test/kaniko rw,noatime master:1 - ext3 /dev/root rw,errors=continue
36 35 98:0 /proc /test/proc rw,noatime master:1 - ext3 /dev/root rw,errors=continue
`
	mFile, err := os.CreateTemp("", "mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	defer mFile.Close()
	if _, err := mFile.WriteString(mountInfo); err != nil {
		t.Fatal(err)
	}
	config.MountInfoPath = mFile.Name()
	defer func() {
		config.MountInfoPath = constants.MountInfoPath
	}()

	expected := []IgnoreListEntry{
		{
			Path:            "/kaniko",
			PrefixMatchOnly: false,
		},
		{
			Path:            "/test/kaniko",
			PrefixMatchOnly: false,
		},
		{
			Path:            "/test/proc",
			PrefixMatchOnly: false,
		},
		{
			Path:            "/etc/mtab",
			PrefixMatchOnly: false,
		},
		{
			Path:            "/tmp/apt-key-gpghome",
			PrefixMatchOnly: true,
		},
	}

	original := append([]IgnoreListEntry{}, ignorelist...)
	defer func() { ignorelist = original }()

	err = InitIgnoreList()
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(expected, func(i, j int) bool {
		return expected[i].Path < expected[j].Path
	})
	sort.Slice(ignorelist, func(i, j int) bool {
		return ignorelist[i].Path < ignorelist[j].Path
	})
	testutil.CheckDeepEqual(t, expected, ignorelist)
}

func Test_setFileTimes(t *testing.T) {
	testDir := t.TempDir()

	p := filepath.Join(testDir, "foo.txt")

	if err := os.WriteFile(p, []byte("meow"), 0o777); err != nil {
		t.Fatal(err)
	}

	type testcase struct {
		desc  string
		path  string
		aTime time.Time
		mTime time.Time
	}

	testCases := []testcase{
		{
			desc: "zero for mod and access",
			path: p,
		},
		{
			desc:  "zero for mod",
			path:  p,
			aTime: time.Now(),
		},
		{
			desc:  "zero for access",
			path:  p,
			mTime: time.Now(),
		},
		{
			desc:  "both non-zero",
			path:  p,
			mTime: time.Now(),
			aTime: time.Now(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			err := setFileTimes(tc.path, tc.aTime, tc.mTime)
			if err != nil {
				t.Errorf("expected err to be nil not %s", err)
			}
		})
	}

}

func TestValidateFilePath(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		expectError bool
	}{
		{
			name:        "Valid relative path with dot",
			path:        ".kaniko/Dockerfile",
			expectError: false,
		},
		{
			name:        "Valid relative path",
			path:        "Dockerfile",
			expectError: false,
		},
		{
			name:        "Valid relative path with subdirectory",
			path:        "src/app/Dockerfile",
			expectError: false,
		},
		{
			name:        "Valid absolute path",
			path:        "/path/to/Dockerfile",
			expectError: false,
		},
		{
			name:        "Invalid path with parent directory",
			path:        "../Dockerfile",
			expectError: true,
		},
		{
			name:        "Invalid path with parent directory in middle",
			path:        "dir/../Dockerfile",
			expectError: true,
		},
		{
			name:        "Invalid path with parent directory at end",
			path:        "path/..",
			expectError: true,
		},
		{
			name:        "Invalid path just parent directory",
			path:        "..",
			expectError: true,
		},
		{
			name:        "Valid path with multiple dots",
			path:        ".../file.txt",
			expectError: false,
		},
		{
			name:        "Valid path with dot in filename",
			path:        ".dockerignore",
			expectError: false,
		},
		{
			name:        "Valid path with dot in directory",
			path:        "./config/.env",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFilePath(tt.path)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for path '%s' but got none", tt.path)
			}

			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for path '%s' but got: %v", tt.path, err)
			}
		})
	}
}

func TestValidateLinkPathName(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		expectError bool
	}{
		{
			name:        "Valid relative link path",
			path:        "link/to/file",
			expectError: false,
		},
		{
			name:        "Valid absolute link path",
			path:        "/absolute/link",
			expectError: false,
		},
		{
			name:        "Invalid link path with parent directory",
			path:        "../link",
			expectError: true,
		},
		{
			name:        "Invalid link path with parent directory in middle",
			path:        "dir/../link",
			expectError: true,
		},
		{
			name:        "Invalid link path just parent directory",
			path:        "..",
			expectError: true,
		},
		{
			name:        "Valid link path with multiple dots",
			path:        ".../link",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLinkPathName(tt.path)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for path '%s' but got none", tt.path)
			}

			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for path '%s' but got: %v", tt.path, err)
			}
		})
	}
}

func TestValidateFileSize(t *testing.T) {
	// Create a temporary file for testing
	tempFile := t.TempDir() + "/test_file.txt"

	// Test with small file (should pass)
	content := "small content"
	if err := os.WriteFile(tempFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Test with valid size
	err := validateFileSize(tempFile, MaxFileSize)
	if err != nil {
		t.Errorf("Expected no error for small file, got: %v", err)
	}

	// Test with very small limit (should fail)
	err = validateFileSize(tempFile, 1)
	if err == nil {
		t.Errorf("Expected error for file exceeding size limit, got nil")
	}

	// Test with non-existent file
	err = validateFileSize("/non/existent/file", MaxFileSize)
	if err == nil {
		t.Errorf("Expected error for non-existent file, got nil")
	}
}

func TestValidateTarFileSize(t *testing.T) {
	tests := []struct {
		name        string
		size        int64
		expectError bool
	}{
		{
			name:        "Valid small size",
			size:        1024,
			expectError: false,
		},
		{
			name:        "Valid medium size",
			size:        100 * 1024 * 1024, // 100MB
			expectError: false,
		},
		{
			name:        "Invalid large size",
			size:        6 * 1024 * 1024 * 1024, // 6GB (exceeds 5GB limit)
			expectError: true,
		},
		{
			name:        "Exact limit size",
			size:        MaxTarFileSize,
			expectError: false,
		},
		{
			name:        "Just over limit size",
			size:        MaxTarFileSize + 1,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTarFileSize(tt.size)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for size %d but got none", tt.size)
			}

			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for size %d but got: %v", tt.size, err)
			}
		})
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    int64
		expectError bool
	}{
		{
			name:        "Valid KB size",
			input:       "1024KB",
			expected:    1024 * 1024,
			expectError: false,
		},
		{
			name:        "Valid MB size",
			input:       "500MB",
			expected:    500 * 1024 * 1024,
			expectError: false,
		},
		{
			name:        "Valid GB size",
			input:       "2GB",
			expected:    2 * 1024 * 1024 * 1024,
			expectError: false,
		},
		{
			name:        "Valid TB size",
			input:       "1TB",
			expected:    1024 * 1024 * 1024 * 1024,
			expectError: false,
		},
		{
			name:        "Valid decimal size",
			input:       "2.5GB",
			expected:    int64(2.5 * 1024 * 1024 * 1024),
			expectError: false,
		},
		{
			name:        "Valid bytes only",
			input:       "1024",
			expected:    1024,
			expectError: false,
		},
		{
			name:        "Invalid format",
			input:       "invalid",
			expected:    0,
			expectError: true,
		},
		{
			name:        "Empty string",
			input:       "",
			expected:    0,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseSize(tt.input)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for input %s but got none", tt.input)
			}

			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for input %s but got: %v", tt.input, err)
			}

			if !tt.expectError && result != tt.expected {
				t.Errorf("Expected %d for input %s but got %d", tt.expected, tt.input, result)
			}
		})
	}
}

func TestGetMaxFileSize(t *testing.T) {
	// Test default value
	result := GetMaxFileSize()
	if result != MaxFileSize {
		t.Errorf("Expected default MaxFileSize %d, got %d", MaxFileSize, result)
	}
}

func TestGetMaxTarFileSize(t *testing.T) {
	// Test default value
	result := GetMaxTarFileSize()
	if result != MaxTarFileSize {
		t.Errorf("Expected default MaxTarFileSize %d, got %d", MaxTarFileSize, result)
	}
}

func TestGetMaxTotalArchiveSize(t *testing.T) {
	// Test default value
	result := GetMaxTotalArchiveSize()
	if result != MaxTotalArchiveSize {
		t.Errorf("Expected default MaxTotalArchiveSize %d, got %d", MaxTotalArchiveSize, result)
	}
}

func TestSetCLISizeLimits(t *testing.T) {
	// Test setting CLI limits
	SetCLISizeLimits("1GB", "10GB", "20GB")

	if getCLIMaxFileSize() != "1GB" {
		t.Errorf("Expected CLI max file size '1GB', got '%s'", getCLIMaxFileSize())
	}

	if getCLIMaxTarFileSize() != "10GB" {
		t.Errorf("Expected CLI max tar file size '10GB', got '%s'", getCLIMaxTarFileSize())
	}

	if getCLIMaxTotalArchiveSize() != "20GB" {
		t.Errorf("Expected CLI max total archive size '20GB', got '%s'", getCLIMaxTotalArchiveSize())
	}
}

func TestGetMaxFileSizeWithCLIOverride(t *testing.T) {
	// Save original environment
	originalEnv := os.Getenv("KANIKO_MAX_FILE_SIZE")
	defer func() {
		if originalEnv != "" {
			os.Setenv("KANIKO_MAX_FILE_SIZE", originalEnv)
		} else {
			os.Unsetenv("KANIKO_MAX_FILE_SIZE")
		}
	}()

	// Clear environment variable
	os.Unsetenv("KANIKO_MAX_FILE_SIZE")

	// Test CLI override
	SetCLISizeLimits("2GB", "", "")
	result := GetMaxFileSize()
	expected := int64(2 * 1024 * 1024 * 1024) // 2GB
	if result != expected {
		t.Errorf("Expected CLI override to return %d, got %d", expected, result)
	}

	// Test invalid CLI value falls back to default
	SetCLISizeLimits("invalid", "", "")
	result = GetMaxFileSize()
	if result != MaxFileSize {
		t.Errorf("Expected invalid CLI value to fall back to default %d, got %d", MaxFileSize, result)
	}
}

func TestGetMaxTarFileSizeWithCLIOverride(t *testing.T) {
	// Save original environment
	originalEnv := os.Getenv("KANIKO_MAX_TAR_FILE_SIZE")
	defer func() {
		if originalEnv != "" {
			os.Setenv("KANIKO_MAX_TAR_FILE_SIZE", originalEnv)
		} else {
			os.Unsetenv("KANIKO_MAX_TAR_FILE_SIZE")
		}
	}()

	// Clear environment variable
	os.Unsetenv("KANIKO_MAX_TAR_FILE_SIZE")

	// Test CLI override
	SetCLISizeLimits("", "15GB", "")
	result := GetMaxTarFileSize()
	expected := int64(15 * 1024 * 1024 * 1024) // 15GB
	if result != expected {
		t.Errorf("Expected CLI override to return %d, got %d", expected, result)
	}
}

func TestGetMaxTotalArchiveSizeWithCLIOverride(t *testing.T) {
	// Save original environment
	originalEnv := os.Getenv("KANIKO_MAX_TOTAL_ARCHIVE_SIZE")
	defer func() {
		if originalEnv != "" {
			os.Setenv("KANIKO_MAX_TOTAL_ARCHIVE_SIZE", originalEnv)
		} else {
			os.Unsetenv("KANIKO_MAX_TOTAL_ARCHIVE_SIZE")
		}
	}()

	// Clear environment variable
	os.Unsetenv("KANIKO_MAX_TOTAL_ARCHIVE_SIZE")

	// Test CLI override
	SetCLISizeLimits("", "", "25GB")
	result := GetMaxTotalArchiveSize()
	expected := int64(25 * 1024 * 1024 * 1024) // 25GB
	if result != expected {
		t.Errorf("Expected CLI override to return %d, got %d", expected, result)
	}
}

func TestSizeLimitPriority(t *testing.T) {
	// Test priority: CLI > Environment > Default

	// Save original environment
	originalEnv := os.Getenv("KANIKO_MAX_FILE_SIZE")
	defer func() {
		if originalEnv != "" {
			os.Setenv("KANIKO_MAX_FILE_SIZE", originalEnv)
		} else {
			os.Unsetenv("KANIKO_MAX_FILE_SIZE")
		}
	}()

	// Set environment variable
	os.Setenv("KANIKO_MAX_FILE_SIZE", "1GB")

	// Test that CLI overrides environment
	SetCLISizeLimits("3GB", "", "")
	result := GetMaxFileSize()
	expected := int64(3 * 1024 * 1024 * 1024) // 3GB
	if result != expected {
		t.Errorf("Expected CLI to override environment: got %d, expected %d", result, expected)
	}

	// Test that environment is used when CLI is empty
	SetCLISizeLimits("", "", "")
	result = GetMaxFileSize()
	expected = int64(1 * 1024 * 1024 * 1024) // 1GB from environment
	if result != expected {
		t.Errorf("Expected environment to be used when CLI is empty: got %d, expected %d", result, expected)
	}

	// Test that default is used when both CLI and environment are empty
	os.Unsetenv("KANIKO_MAX_FILE_SIZE")
	SetCLISizeLimits("", "", "")
	result = GetMaxFileSize()
	if result != MaxFileSize {
		t.Errorf("Expected default to be used when CLI and environment are empty: got %d, expected %d", result, MaxFileSize)
	}
}

func TestValidateSymlinkChain(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		setup       func() string // Returns the symlink path to test
		expectError bool
		errorMsg    string
	}{
		{
			name: "Valid single symlink",
			setup: func() string {
				target := filepath.Join(tempDir, "target")
				os.WriteFile(target, []byte("test"), 0644)

				symlink := filepath.Join(tempDir, "link")
				os.Symlink(target, symlink)
				return symlink
			},
			expectError: false,
		},
		{
			name: "Circular symlink reference",
			setup: func() string {
				symlink := filepath.Join(tempDir, "circular")
				os.Symlink("circular", symlink) // Points to itself
				return symlink
			},
			expectError: true,
			errorMsg:    "circular symlink reference detected",
		},
		{
			name: "Symlink chain too deep",
			setup: func() string {
				// Create a chain of 12 symlinks (exceeds max depth of 10)
				// Start with a regular file
				target := filepath.Join(tempDir, "target")
				os.WriteFile(target, []byte("test"), 0644)

				// Create a chain: link0 -> link1 -> ... -> link11 -> target
				// Each link points to the next one, creating a chain
				prev := target
				for i := 0; i < 12; i++ {
					next := filepath.Join(tempDir, fmt.Sprintf("link%d", i))
					// Each symlink points to the previous one
					os.Symlink(prev, next)
					prev = next
				}
				return prev // This is link11, the last in the chain
			},
			expectError: true,
			errorMsg:    "symlink chain too deep",
		},
		{
			name: "Non-symlink file",
			setup: func() string {
				file := filepath.Join(tempDir, "regular_file")
				os.WriteFile(file, []byte("test"), 0644)
				return file
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			symlinkPath := tt.setup()
			err := validateSymlinkChain(symlinkPath, 0)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestValidateSymlinkTarget(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name        string
		target      string
		sourcePath  string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid relative target",
			target:      "subdir/file",
			sourcePath:  filepath.Join(tempDir, "link"),
			expectError: false,
		},
		{
			name:        "Valid relative target with subdirectory",
			target:      "../sibling/file",
			sourcePath:  filepath.Join(tempDir, "subdir", "link"),
			expectError: false,
		},
		{
			name:        "Traversal attempt - too many ..",
			target:      "../../../etc/passwd",
			sourcePath:  filepath.Join(tempDir, "subdir", "link"),
			expectError: true,
			errorMsg:    "would escape source directory",
		},
		{
			name:        "Dangerous absolute path - /etc",
			target:      "/etc/passwd",
			sourcePath:  filepath.Join(tempDir, "link"),
			expectError: true,
			errorMsg:    "points to dangerous path",
		},
		{
			name:        "Dangerous absolute path - /proc",
			target:      "/proc/self/environ",
			sourcePath:  filepath.Join(tempDir, "link"),
			expectError: true,
			errorMsg:    "points to dangerous path",
		},
		{
			name:        "Valid absolute path in safe directory",
			target:      "/tmp/safe_file",
			sourcePath:  filepath.Join(tempDir, "link"),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSymlinkTarget(tt.target, tt.sourcePath)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestValidateAbsoluteSymlinkTarget(t *testing.T) {
	tests := []struct {
		name        string
		target      string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Safe absolute path",
			target:      "/tmp/safe_file",
			expectError: false,
		},
		{
			name:        "Safe absolute path with subdirectory",
			target:      "/usr/local/bin/command",
			expectError: false,
		},
		{
			name:        "Dangerous path - /etc",
			target:      "/etc/passwd",
			expectError: true,
			errorMsg:    "points to dangerous path",
		},
		{
			name:        "Dangerous path - /proc",
			target:      "/proc/self/environ",
			expectError: true,
			errorMsg:    "points to dangerous path",
		},
		{
			name:        "Dangerous path - /sys",
			target:      "/sys/kernel/debug",
			expectError: true,
			errorMsg:    "points to dangerous path",
		},
		{
			name:        "Dangerous path - /dev",
			target:      "/dev/null",
			expectError: true,
			errorMsg:    "points to dangerous path",
		},
		{
			name:        "Dangerous path - /root",
			target:      "/root/.ssh/id_rsa",
			expectError: true,
			errorMsg:    "points to dangerous path",
		},
		{
			name:        "Dangerous path - /home",
			target:      "/home/user/.bashrc",
			expectError: true,
			errorMsg:    "points to dangerous path",
		},
		{
			name:        "Dangerous path - /var/log",
			target:      "/var/log/auth.log",
			expectError: true,
			errorMsg:    "points to dangerous path",
		},
		{
			name:        "Dangerous path - /var/run",
			target:      "/var/run/docker.sock",
			expectError: true,
			errorMsg:    "points to dangerous path",
		},
		{
			name:        "Traversal in absolute path",
			target:      "/tmp/../etc/passwd",
			expectError: true,
			errorMsg:    "contains directory traversal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAbsoluteSymlinkTarget(tt.target)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestValidateDirectoryPermissions(t *testing.T) {
	tests := []struct {
		name        string
		mode        os.FileMode
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid directory permissions",
			mode:        0755,
			expectError: false,
		},
		{
			name:        "Valid restrictive permissions",
			mode:        0700,
			expectError: false,
		},
		{
			name:        "World-writable directory (warning)",
			mode:        0777,
			expectError: false, // Should warn but not error
		},
		{
			name:        "No owner permissions",
			mode:        0000,
			expectError: true,
			errorMsg:    "directory must have at least owner permissions",
		},
		{
			name:        "Only group permissions",
			mode:        0070,
			expectError: true,
			errorMsg:    "directory must have at least owner permissions",
		},
		{
			name:        "Only world permissions",
			mode:        0007,
			expectError: true,
			errorMsg:    "directory must have at least owner permissions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDirectoryPermissions(tt.mode)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestValidateUserGroupIDs(t *testing.T) {
	tests := []struct {
		name        string
		uid         int64
		gid         int64
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid UID/GID",
			uid:         1000,
			gid:         1000,
			expectError: false,
		},
		{
			name:        "Root UID/GID",
			uid:         0,
			gid:         0,
			expectError: false,
		},
		{
			name:        "Negative UID",
			uid:         -1,
			gid:         1000,
			expectError: true,
			errorMsg:    "UID and GID must be non-negative",
		},
		{
			name:        "Negative GID",
			uid:         1000,
			gid:         -1,
			expectError: true,
			errorMsg:    "UID and GID must be non-negative",
		},
		{
			name:        "High UID/GID (warning)",
			uid:         2000000,
			gid:         2000000,
			expectError: false, // Should warn but not error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUserGroupIDs(tt.uid, tt.gid)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestValidateFilePermissions(t *testing.T) {
	tests := []struct {
		name        string
		mode        os.FileMode
		expectError bool
		errorMsg    string
	}{
		{
			name:        "Valid file permissions",
			mode:        0644,
			expectError: false,
		},
		{
			name:        "Valid executable file",
			mode:        0755,
			expectError: false,
		},
		{
			name:        "World-writable file (warning)",
			mode:        0666,
			expectError: false, // Should warn but not error
		},
		{
			name:        "No owner permissions",
			mode:        0000,
			expectError: true,
			errorMsg:    "file must have at least owner permissions",
		},
		{
			name:        "Only group permissions",
			mode:        0060,
			expectError: true,
			errorMsg:    "file must have at least owner permissions",
		},
		{
			name:        "Only world permissions",
			mode:        0006,
			expectError: true,
			errorMsg:    "file must have at least owner permissions",
		},
		{
			name:        "World-readable and executable",
			mode:        0755,
			expectError: false, // Should warn but not error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFilePermissions(tt.mode)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error message to contain '%s', got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}
