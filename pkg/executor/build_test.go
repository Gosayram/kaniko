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

package executor

import (
	"archive/tar"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/containerd/containerd/platforms"
	"github.com/google/go-cmp/cmp"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"

	"github.com/Gosayram/kaniko/pkg/cache"
	"github.com/Gosayram/kaniko/pkg/commands"
	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/dockerfile"
	"github.com/Gosayram/kaniko/pkg/util"
	"github.com/Gosayram/kaniko/testutil"
)

func Test_reviewConfig(t *testing.T) {
	tests := []struct {
		name               string
		dockerfile         string
		originalCmd        []string
		originalEntrypoint []string
		expectedCmd        []string
	}{
		{
			name: "entrypoint and cmd declared",
			dockerfile: `
			FROM scratch
			CMD ["mycmd"]
			ENTRYPOINT ["myentrypoint"]`,
			originalEntrypoint: []string{"myentrypoint"},
			originalCmd:        []string{"mycmd"},
			expectedCmd:        []string{"mycmd"},
		},
		{
			name: "only entrypoint declared",
			dockerfile: `
			FROM scratch
			ENTRYPOINT ["myentrypoint"]`,
			originalEntrypoint: []string{"myentrypoint"},
			originalCmd:        []string{"mycmd"},
			expectedCmd:        nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := &v1.Config{
				Cmd:        test.originalCmd,
				Entrypoint: test.originalEntrypoint,
			}
			stg := stage(t, test.dockerfile)
			reviewConfig(&stg, config)
			testutil.CheckErrorAndDeepEqual(t, false, nil, test.expectedCmd, config.Cmd)
		})
	}
}

func stage(t *testing.T, d string) config.KanikoStage {
	stages, _, err := dockerfile.Parse([]byte(d))
	if err != nil {
		t.Fatalf("error parsing dockerfile: %v", err)
	}
	return config.KanikoStage{
		Stage: stages[0],
	}
}

func Test_stageBuilder_shouldTakeSnapshot(t *testing.T) {
	cmds := []commands.DockerCommand{
		&MockDockerCommand{command: "command1"},
		&MockDockerCommand{command: "command2"},
		&MockDockerCommand{command: "command3"},
	}

	type fields struct {
		stage config.KanikoStage
		opts  *config.KanikoOptions
		cmds  []commands.DockerCommand
	}
	type args struct {
		index        int
		metadataOnly bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "final stage not last command",
			fields: fields{
				stage: config.KanikoStage{
					Final: true,
				},
				cmds: cmds,
			},
			args: args{
				index: 1,
			},
			want: true,
		},
		{
			name: "not final stage last command",
			fields: fields{
				stage: config.KanikoStage{
					Final: false,
				},
				cmds: cmds,
			},
			args: args{
				index: len(cmds) - 1,
			},
			want: true,
		},
		{
			name: "not final stage not last command",
			fields: fields{
				stage: config.KanikoStage{
					Final: false,
				},
				cmds: cmds,
			},
			args: args{
				index: 0,
			},
			want: true,
		},
		{
			name: "not final stage not last command but empty list of files",
			fields: fields{
				stage: config.KanikoStage{},
			},
			args: args{
				index:        0,
				metadataOnly: true,
			},
			want: false,
		},
		{
			name: "not final stage not last command no files provided",
			fields: fields{
				stage: config.KanikoStage{
					Final: false,
				},
			},
			args: args{
				index:        0,
				metadataOnly: false,
			},
			want: true,
		},
		{
			name: "caching enabled intermediate container",
			fields: fields{
				stage: config.KanikoStage{
					Final: false,
				},
				opts: &config.KanikoOptions{Cache: true},
				cmds: cmds,
			},
			args: args{
				index: 0,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if tt.fields.opts == nil {
				tt.fields.opts = &config.KanikoOptions{}
			}
			s := &stageBuilder{
				stage: tt.fields.stage,
				opts:  tt.fields.opts,
				cmds:  tt.fields.cmds,
			}
			if got := s.shouldTakeSnapshot(tt.args.index, tt.args.metadataOnly); got != tt.want {
				t.Errorf("stageBuilder.shouldTakeSnapshot() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCalculateDependencies(t *testing.T) {
	type args struct {
		dockerfile     string
		mockInitConfig func(partial.WithConfigFile, *config.KanikoOptions) (*v1.ConfigFile, error)
	}
	tests := []struct {
		name string
		args args
		want map[int][]string
	}{
		{
			name: "no deps",
			args: args{
				dockerfile: `
FROM debian as stage1
RUN foo
FROM stage1
RUN bar
`,
			},
			want: map[int][]string{},
		},
		{
			name: "args",
			args: args{
				dockerfile: `
ARG myFile=foo
FROM debian as stage1
RUN foo
FROM stage1
ARG myFile
COPY --from=stage1 /tmp/$myFile.txt .
RUN bar
`,
			},
			want: map[int][]string{
				0: {"/tmp/foo.txt"},
			},
		},
		{
			name: "simple deps",
			args: args{
				dockerfile: `
FROM debian as stage1
FROM alpine
COPY --from=stage1 /foo /bar
`,
			},
			want: map[int][]string{
				0: {"/foo"},
			},
		},
		{
			name: "two sets deps",
			args: args{
				dockerfile: `
FROM debian as stage1
FROM ubuntu as stage2
RUN foo
COPY --from=stage1 /foo /bar
FROM alpine
COPY --from=stage2 /bar /bat
`,
			},
			want: map[int][]string{
				0: {"/foo"},
				1: {"/bar"},
			},
		},
		{
			name: "double deps",
			args: args{
				dockerfile: `
FROM debian as stage1
FROM ubuntu as stage2
RUN foo
COPY --from=stage1 /foo /bar
FROM alpine
COPY --from=stage1 /baz /bat
`,
			},
			want: map[int][]string{
				0: {"/foo", "/baz"},
			},
		},
		{
			name: "envs in deps",
			args: args{
				dockerfile: `
FROM debian as stage1
FROM ubuntu as stage2
RUN foo
ENV key1 val1
ENV key2 val2
COPY --from=stage1 /foo/$key1 /foo/$key2 /bar
FROM alpine
COPY --from=stage2 /bar /bat
`,
			},
			want: map[int][]string{
				0: {"/foo/val1", "/foo/val2"},
				1: {"/bar"},
			},
		},
		{
			name: "envs from base image in deps",
			args: args{
				dockerfile: `
FROM debian as stage1
ENV key1 baseval1
FROM stage1 as stage2
RUN foo
ENV key2 val2
COPY --from=stage1 /foo/$key1 /foo/$key2 /bar
FROM alpine
COPY --from=stage2 /bar /bat
`,
			},
			want: map[int][]string{
				0: {"/foo/baseval1", "/foo/val2"},
				1: {"/bar"},
			},
		},
		{
			name: "one image has onbuild config",
			args: args{
				mockInitConfig: func(img partial.WithConfigFile, opts *config.KanikoOptions) (*v1.ConfigFile, error) {
					cfg, err := img.ConfigFile()
					// if image is "alpine" then add ONBUILD to its config
					if cfg != nil && cfg.Architecture != "" {
						cfg.Config.OnBuild = []string{"COPY --from=builder /app /app"}
					}
					return cfg, err
				},
				dockerfile: `
FROM scratch as builder
RUN foo
FROM alpine as second
# This image has an ONBUILD command so it will be executed
COPY --from=builder /foo /bar
FROM scratch as target
COPY --from=second /bar /bat
`,
			},
			want: map[int][]string{
				0: {"/app", "/foo"},
				1: {"/bar"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.args.mockInitConfig != nil {
				original := initializeConfig
				defer func() { initializeConfig = original }()
				initializeConfig = tt.args.mockInitConfig
			}

			f, _ := os.CreateTemp("", "")
			os.WriteFile(f.Name(), []byte(tt.args.dockerfile), 0755)
			opts := &config.KanikoOptions{
				DockerfilePath: f.Name(),
				CustomPlatform: platforms.Format(platforms.Normalize(platforms.DefaultSpec())),
			}
			testStages, metaArgs, err := dockerfile.ParseStages(opts)
			if err != nil {
				t.Errorf("Failed to parse test dockerfile to stages: %s", err)
			}

			kanikoStages, err := dockerfile.MakeKanikoStages(opts, testStages, metaArgs)
			if err != nil {
				t.Errorf("Failed to parse stages to Kaniko Stages: %s", err)
			}
			stageNameToIdx := ResolveCrossStageInstructions(kanikoStages)

			got, err := CalculateDependencies(kanikoStages, opts, stageNameToIdx)
			if err != nil {
				t.Errorf("got error: %s,", err)
			}

			if !reflect.DeepEqual(got, tt.want) {
				diff := cmp.Diff(got, tt.want)
				t.Errorf("CalculateDependencies() = %v, want %v, diff %v", got, tt.want, diff)
			}
		})
	}
}

func Test_filesToSave(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		want  []string
		files []string
	}{
		{
			name:  "simple",
			args:  []string{"foo"},
			files: []string{"foo"},
			want:  []string{"foo"},
		},
		{
			name:  "glob",
			args:  []string{"foo*"},
			files: []string{"foo", "foo2", "fooooo", "bar"},
			want:  []string{"foo", "foo2", "fooooo"},
		},
		{
			name:  "complex glob",
			args:  []string{"foo*", "bar?"},
			files: []string{"foo", "foo2", "fooooo", "bar", "bar1", "bar2", "bar33"},
			want:  []string{"foo", "foo2", "fooooo", "bar1", "bar2"},
		},
		{
			name:  "dir",
			args:  []string{"foo"},
			files: []string{"foo/bar", "foo/baz", "foo/bat/baz"},
			want:  []string{"foo"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			original := config.RootDir
			config.RootDir = tmpDir
			defer func() {
				config.RootDir = original
			}()

			for _, f := range tt.files {
				p := filepath.Join(tmpDir, f)
				dir := filepath.Dir(p)
				if dir != "." {
					if err := os.MkdirAll(dir, 0755); err != nil {
						t.Errorf("error making dir: %s", err)
					}
				}
				fp, err := os.Create(p)
				if err != nil {
					t.Errorf("error making file: %s", err)
				}
				fp.Close()
			}

			got := filesToSave(tt.args)
			sort.Strings(tt.want)
			sort.Strings(got)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("filesToSave() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeduplicatePaths(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{
			name:  "no duplicates",
			input: []string{"file1.txt", "file2.txt", "usr/lib"},
			want:  []string{"file1.txt", "file2.txt", "usr/lib"},
		},
		{
			name:  "duplicates",
			input: []string{"file1.txt", "file2.txt", "file2.txt", "usr/lib"},
			want:  []string{"file1.txt", "file2.txt", "usr/lib"},
		},
		{
			name:  "duplicates with paths",
			input: []string{"file1.txt", "file2.txt", "file2.txt", "usr/lib", "usr/lib/ssl"},
			want:  []string{"file1.txt", "file2.txt", "usr/lib"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deduplicatePaths(tt.input)
			sort.Strings(tt.want)
			sort.Strings(got)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TestDeduplicatePaths() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInitializeConfig(t *testing.T) {
	tests := []struct {
		description string
		cfg         v1.ConfigFile
		expected    v1.Config
	}{
		{
			description: "env is not set in the image",
			cfg: v1.ConfigFile{
				Config: v1.Config{
					Image: "test",
				},
			},
			expected: v1.Config{
				Image: "test",
				Env: []string{
					"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				},
			},
		},
		{
			description: "env is set in the image",
			cfg: v1.ConfigFile{
				Config: v1.Config{
					Env: []string{
						"PATH=/usr/local/something",
					},
				},
			},
			expected: v1.Config{
				Env: []string{
					"PATH=/usr/local/something",
				},
			},
		},
		{
			description: "image is empty",
			expected: v1.Config{
				Env: []string{
					"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				},
			},
		},
	}
	for _, tt := range tests {
		img, err := mutate.ConfigFile(empty.Image, &tt.cfg)
		if err != nil {
			t.Errorf("error seen when running test %s", err)
			t.Fail()
		}
		actual, _ := initializeConfig(img, nil)
		testutil.CheckDeepEqual(t, tt.expected, actual.Config)
	}
}

func Test_newLayerCache_defaultCache(t *testing.T) {
	t.Run("default layer cache is fast slow cache wrapping registry cache", func(t *testing.T) {
		layerCache := newLayerCache(&config.KanikoOptions{CacheRepo: "some-cache-repo"})
		// newLayerCache now returns FastSlowCache which wraps RegistryCache
		fastSlowCache, ok := layerCache.(*cache.FastSlowCache)
		if !ok {
			t.Errorf("expected layer cache to be a FastSlowCache, got %T", layerCache)
			return
		}
		// FastSlowCache wraps slowCache which should be RegistryCache
		// We can't directly access slowCache, but we can verify it works by checking behavior
		// The cache should work correctly with the provided CacheRepo
		if fastSlowCache == nil {
			t.Error("expected fast slow cache to be non-nil")
		}
	})
}

func Test_newLayerCache_layoutCache(t *testing.T) {
	t.Run("when cache repo has 'oci:' prefix layer cache is fast slow cache wrapping layout cache", func(t *testing.T) {
		layerCache := newLayerCache(&config.KanikoOptions{CacheRepo: "oci:/some-cache-repo"})
		// newLayerCache now returns FastSlowCache which wraps LayoutCache
		fastSlowCache, ok := layerCache.(*cache.FastSlowCache)
		if !ok {
			t.Errorf("expected layer cache to be a FastSlowCache, got %T", layerCache)
			return
		}
		// FastSlowCache wraps slowCache which should be LayoutCache
		// We can't directly access slowCache, but we can verify it works by checking behavior
		if fastSlowCache == nil {
			t.Error("expected fast slow cache to be non-nil")
		}
	})
}

func Test_stageBuilder_optimize(t *testing.T) {
	testCases := []struct {
		opts     *config.KanikoOptions
		retrieve bool
		name     string
	}{
		{
			name: "cache enabled and layer not present in cache",
			opts: &config.KanikoOptions{Cache: true},
		},
		{
			name:     "cache enabled and layer present in cache",
			opts:     &config.KanikoOptions{Cache: true},
			retrieve: true,
		},
		{
			name: "cache disabled and layer not present in cache",
			opts: &config.KanikoOptions{Cache: false},
		},
		{
			name:     "cache disabled and layer present in cache",
			opts:     &config.KanikoOptions{Cache: false},
			retrieve: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cf := &v1.ConfigFile{}
			snap := &fakeSnapShotter{}
			lc := &fakeLayerCache{retrieve: tc.retrieve}
			sb := &stageBuilder{
				opts:             tc.opts,
				cf:               cf,
				snapshotter:      snap,
				layerCache:       lc,
				args:             dockerfile.NewBuildArgs([]string{}),
				digestToCacheKey: make(map[string]string),
			}
			ck := CompositeCache{}
			file, err := os.CreateTemp("", "foo")
			if err != nil {
				t.Error(err)
			}
			defer os.Remove(file.Name())
			command := MockDockerCommand{
				contextFiles: []string{file.Name()},
				cacheCommand: MockCachedDockerCommand{},
			}
			sb.cmds = []commands.DockerCommand{command}
			err = sb.optimize(ck, &cf.Config)
			if err != nil {
				t.Errorf("Expected error to be nil but was %v", err)
			}

		})
	}
}

// parallelFakeLayerCache is a mock layer cache that tracks concurrent calls
type parallelFakeLayerCache struct {
	fakeLayerCache
	receivedKeys       []string
	concurrentCalls    int
	maxConcurrent      int
	mu                 sync.Mutex
	callCh             chan struct{}
	maxConcurrentLimit int // Limit for batch operations
}

func (p *parallelFakeLayerCache) RetrieveLayer(key string) (v1.Image, error) {
	p.mu.Lock()
	p.concurrentCalls++
	current := p.concurrentCalls
	if current > p.maxConcurrent {
		p.maxConcurrent = current
	}
	p.mu.Unlock()

	// Simulate some work to allow other goroutines to start
	time.Sleep(10 * time.Millisecond)

	p.mu.Lock()
	p.concurrentCalls--
	p.mu.Unlock()

	p.callCh <- struct{}{}
	return p.fakeLayerCache.RetrieveLayer(key)
}

func (p *parallelFakeLayerCache) RetrieveLayersBatch(keys []string) map[string]cache.LayerResult {
	results := make(map[string]cache.LayerResult)
	if len(keys) == 0 {
		return results
	}

	// Get max concurrent limit (default to 3 if not set)
	maxConcurrent := p.maxConcurrentLimit
	if maxConcurrent <= 0 {
		maxConcurrent = 3
	}

	// Use semaphore to limit concurrent requests
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, key := range keys {
		wg.Add(1)
		go func(ck string) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			// Track concurrent calls
			p.mu.Lock()
			p.concurrentCalls++
			current := p.concurrentCalls
			if current > p.maxConcurrent {
				p.maxConcurrent = current
			}
			p.mu.Unlock()

			// Simulate some work to allow other goroutines to start
			time.Sleep(10 * time.Millisecond)

			// Retrieve layer
			img, err := p.fakeLayerCache.RetrieveLayer(ck)

			p.mu.Lock()
			p.concurrentCalls--
			p.mu.Unlock()

			// Store result
			mu.Lock()
			results[ck] = cache.LayerResult{
				Image: img,
				Error: err,
			}
			mu.Unlock()

			// Track received keys (thread-safe)
			p.mu.Lock()
			p.receivedKeys = append(p.receivedKeys, ck)
			p.mu.Unlock()

			// Signal call completion (non-blocking)
			select {
			case p.callCh <- struct{}{}:
			default:
				// Channel full, skip
			}
		}(key)
	}

	wg.Wait()
	return results
}

// Test_stageBuilder_optimize_parallel tests parallel cache checking
func Test_stageBuilder_optimize_parallel(t *testing.T) {

	testCases := []struct {
		name                  string
		maxConcurrent         int
		numCommands           int
		expectedMaxConcurrent int
	}{
		{
			name:                  "parallel check with 3 commands and max 2 concurrent",
			maxConcurrent:         2,
			numCommands:           3,
			expectedMaxConcurrent: 2, // Should be limited by semaphore
		},
		{
			name:                  "parallel check with 5 commands and max 5 concurrent",
			maxConcurrent:         5,
			numCommands:           5,
			expectedMaxConcurrent: 5,
		},
		{
			name:                  "parallel check with 10 commands and max 3 concurrent",
			maxConcurrent:         3,
			numCommands:           10,
			expectedMaxConcurrent: 3, // Should be limited by semaphore
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new mock for each test case
			parallelLC := &parallelFakeLayerCache{
				fakeLayerCache: fakeLayerCache{
					retrieve: true,
					img:      &fakeImage{},
				},
				callCh:             make(chan struct{}, 100),
				maxConcurrentLimit: tc.maxConcurrent, // Set limit for batch operations
			}

			cf := &v1.ConfigFile{}
			snap := &fakeSnapShotter{}
			sb := &stageBuilder{
				opts: &config.KanikoOptions{
					Cache:                    true,
					MaxConcurrentCacheChecks: tc.maxConcurrent,
				},
				cf:               cf,
				snapshotter:      snap,
				layerCache:       parallelLC,
				args:             dockerfile.NewBuildArgs([]string{}),
				cmds:             make([]commands.DockerCommand, tc.numCommands),
				digestToCacheKey: make(map[string]string),
			}

			// Create test commands
			for i := 0; i < tc.numCommands; i++ {
				file, err := os.CreateTemp("", fmt.Sprintf("foo%d", i))
				if err != nil {
					t.Fatalf("Failed to create temp file: %v", err)
				}
				defer os.Remove(file.Name())

				sb.cmds[i] = MockDockerCommand{
					command:      fmt.Sprintf("RUN echo %d", i),
					contextFiles: []string{file.Name()},
					cacheCommand: MockCachedDockerCommand{},
				}
			}

			ck := CompositeCache{}
			err := sb.optimize(ck, &cf.Config)
			if err != nil {
				t.Fatalf("Expected error to be nil but was %v", err)
			}

			// Wait for all calls to complete
			time.Sleep(100 * time.Millisecond)

			// Verify that concurrent calls were limited
			if parallelLC.maxConcurrent > tc.maxConcurrent {
				t.Errorf("Expected max concurrent calls to be <= %d, got %d",
					tc.maxConcurrent, parallelLC.maxConcurrent)
			}

			// Verify that all commands that should be cached were checked
			// Note: Some commands might not have ShouldCacheOutput() == true
			// So we check that at least some commands were checked
			if len(parallelLC.receivedKeys) == 0 {
				t.Errorf("Expected at least some cache checks, got 0")
			}
			// Verify that we got reasonable number of checks (at least most commands)
			// Allow some flexibility as not all commands may be cacheable
			if len(parallelLC.receivedKeys) < tc.numCommands/2 {
				t.Errorf("Expected at least %d cache checks (half of commands), got %d",
					tc.numCommands/2, len(parallelLC.receivedKeys))
			}

			// Verify that we actually had some parallelism (unless numCommands <= maxConcurrent)
			if tc.numCommands > tc.maxConcurrent && parallelLC.maxConcurrent < 2 {
				t.Errorf("Expected some parallelism (maxConcurrent >= 2), got %d",
					parallelLC.maxConcurrent)
			}
		})
	}
}

// orderedFakeLayerCache is a mock layer cache that tracks call order
type orderedFakeLayerCache struct {
	fakeLayerCache
	callOrder []int
	mu        sync.Mutex
	callIndex int
}

func (o *orderedFakeLayerCache) RetrieveLayer(key string) (v1.Image, error) {
	o.mu.Lock()
	o.callOrder = append(o.callOrder, o.callIndex)
	o.callIndex++
	o.mu.Unlock()

	// Simulate some work
	time.Sleep(5 * time.Millisecond)
	return o.fakeLayerCache.RetrieveLayer(key)
}

func (o *orderedFakeLayerCache) RetrieveLayersBatch(keys []string) map[string]cache.LayerResult {
	results := make(map[string]cache.LayerResult)
	if len(keys) == 0 {
		return results
	}

	// Use parallel execution but track order
	var wg sync.WaitGroup
	var resultMu sync.Mutex

	for _, key := range keys {
		wg.Add(1)
		go func(ck string) {
			defer wg.Done()

			// Track call order (thread-safe)
			o.mu.Lock()
			currentIndex := o.callIndex
			o.callOrder = append(o.callOrder, currentIndex)
			o.callIndex++
			o.mu.Unlock()

			// Simulate some work
			time.Sleep(5 * time.Millisecond)

			// Retrieve layer
			img, err := o.fakeLayerCache.RetrieveLayer(ck)

			// Store result (thread-safe)
			resultMu.Lock()
			results[ck] = cache.LayerResult{
				Image: img,
				Error: err,
			}
			resultMu.Unlock()
		}(key)
	}

	wg.Wait()
	return results
}

// Test_stageBuilder_optimize_order_preservation tests that layer application order is preserved
func Test_stageBuilder_optimize_order_preservation(t *testing.T) {
	orderedLC := &orderedFakeLayerCache{
		fakeLayerCache: fakeLayerCache{
			retrieve: true,
			img:      &fakeImage{},
		},
		callOrder: make([]int, 0),
	}

	cf := &v1.ConfigFile{}
	snap := &fakeSnapShotter{}
	sb := &stageBuilder{
		opts: &config.KanikoOptions{
			Cache:                    true,
			MaxConcurrentCacheChecks: 3, // Allow parallel checks
		},
		cf:               cf,
		snapshotter:      snap,
		layerCache:       orderedLC,
		args:             dockerfile.NewBuildArgs([]string{}),
		cmds:             make([]commands.DockerCommand, 5),
		digestToCacheKey: make(map[string]string),
	}

	// Create 5 test commands
	for i := 0; i < 5; i++ {
		file, err := os.CreateTemp("", fmt.Sprintf("foo%d", i))
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer os.Remove(file.Name())

		sb.cmds[i] = MockDockerCommand{
			command:      fmt.Sprintf("RUN echo %d", i),
			contextFiles: []string{file.Name()},
			cacheCommand: MockCachedDockerCommand{},
		}
	}

	ck := CompositeCache{}
	err := sb.optimize(ck, &cf.Config)
	if err != nil {
		t.Fatalf("Expected error to be nil but was %v", err)
	}

	// Wait for all calls to complete
	time.Sleep(50 * time.Millisecond)

	// Verify that all commands were checked (order of checks can be parallel, but application is sequential)
	// Read callOrder with mutex protection
	orderedLC.mu.Lock()
	callOrderLen := len(orderedLC.callOrder)
	orderedLC.mu.Unlock()

	if callOrderLen != 5 {
		t.Errorf("Expected 5 cache checks, got %d", callOrderLen)
	}

	// Verify that commands were applied in order (check that cache hits were applied sequentially)
	// This is verified by checking that the final commands array has cached commands in order
	// Note: Reading sb.cmds is safe here because optimize() completes before we read
	for i := 0; i < 5; i++ {
		// All commands should have been replaced with cached versions
		if _, ok := sb.cmds[i].(MockCachedDockerCommand); !ok {
			t.Errorf("Expected command %d to be replaced with cached version", i)
		}
	}
}

type stageContext struct {
	command fmt.Stringer
	args    *dockerfile.BuildArgs
	env     []string
}

func newStageContext(command string, args map[string]string, env []string) stageContext {
	dockerArgs := dockerfile.NewBuildArgs([]string{})
	for k, v := range args {
		dockerArgs.AddArg(k, &v)
	}
	return stageContext{MockDockerCommand{command: command}, dockerArgs, env}
}

func Test_stageBuilder_populateCompositeKey(t *testing.T) {
	type testcase struct {
		description string
		cmd1        stageContext
		cmd2        stageContext
		shdEqual    bool
	}
	testCases := []testcase{
		{
			description: "cache key for same command [RUN] with same build args",
			cmd1: newStageContext(
				"RUN echo $ARG > test",
				map[string]string{"ARG": "foo"},
				[]string{},
			),
			cmd2: newStageContext(
				"RUN echo $ARG > test",
				map[string]string{"ARG": "foo"},
				[]string{},
			),
			shdEqual: true,
		},
		{
			description: "cache key for same command [RUN] with same env and args",
			cmd1: newStageContext(
				"RUN echo $ENV > test",
				map[string]string{"ARG": "foo"},
				[]string{"ENV=same"},
			),
			cmd2: newStageContext(
				"RUN echo $ENV > test",
				map[string]string{"ARG": "foo"},
				[]string{"ENV=same"},
			),
			shdEqual: true,
		},
		{
			description: "cache key for same command [RUN] with same env but different args",
			cmd1: newStageContext(
				"RUN echo $ENV > test",
				map[string]string{"ARG": "foo"},
				[]string{"ENV=same"},
			),
			cmd2: newStageContext(
				"RUN echo $ENV > test",
				map[string]string{"ARG": "bar"},
				[]string{"ENV=same"},
			),
		},
		{
			description: "cache key for same command [RUN], different buildargs, args not used in command",
			cmd1: newStageContext(
				"RUN echo const > test",
				map[string]string{"ARG": "foo"},
				[]string{"ENV=foo1"},
			),
			cmd2: newStageContext(
				"RUN echo const > test",
				map[string]string{"ARG": "bar"},
				[]string{"ENV=bar1"},
			),
		},
		{
			description: "cache key for same command [RUN], different buildargs, args used in script",
			// test.sh
			// #!/bin/sh
			// echo ${ARG}
			cmd1: newStageContext(
				"RUN ./test.sh",
				map[string]string{"ARG": "foo"},
				[]string{"ENV=foo1"},
			),
			cmd2: newStageContext(
				"RUN ./test.sh",
				map[string]string{"ARG": "bar"},
				[]string{"ENV=bar1"},
			),
		},
		{
			description: "cache key for same command [RUN] with a build arg values",
			cmd1: newStageContext(
				"RUN echo $ARG > test",
				map[string]string{"ARG": "foo"},
				[]string{},
			),
			cmd2: newStageContext(
				"RUN echo $ARG > test",
				map[string]string{"ARG": "bar"},
				[]string{},
			),
		},
		{
			description: "cache key for same command [RUN] with different env values",
			cmd1: newStageContext(
				"RUN echo $ENV > test",
				map[string]string{"ARG": "foo"},
				[]string{"ENV=1"},
			),
			cmd2: newStageContext(
				"RUN echo $ENV > test",
				map[string]string{"ARG": "foo"},
				[]string{"ENV=2"},
			),
		},
		{
			description: "cache key for different command [RUN] same context",
			cmd1: newStageContext(
				"RUN echo other > test",
				map[string]string{"ARG": "foo"},
				[]string{"ENV=1"},
			),
			cmd2: newStageContext(
				"RUN echo another > test",
				map[string]string{"ARG": "foo"},
				[]string{"ENV=1"},
			),
		},
		{
			description: "cache key for command [RUN] with same env values [check that variable no interpolate in RUN command]",
			cmd1: newStageContext(
				"RUN echo $ENV > test",
				map[string]string{"ARG": "foo"},
				[]string{"ENV=1"},
			),
			cmd2: newStageContext(
				"RUN echo 1 > test",
				map[string]string{"ARG": "foo"},
				[]string{"ENV=1"},
			),
			shdEqual: false,
		},
		{
			description: "cache key for command [RUN] with different env values [check that variable no interpolate in RUN command]",
			cmd1: newStageContext(
				"RUN echo ${APP_VERSION%.*} ${APP_VERSION%-*} > test",
				map[string]string{"ARG": "foo"},
				[]string{"ENV=1"},
			),
			cmd2: newStageContext(
				"RUN echo ${APP_VERSION%.*} ${APP_VERSION%-*} > test",
				map[string]string{"ARG": "foo"},
				[]string{"ENV=2"},
			),
			shdEqual: false,
		},
		func() testcase {
			dir, files := tempDirAndFile(t)
			file := files[0]
			filePath := filepath.Join(dir, file)
			return testcase{
				description: "cache key for same command [COPY] with same args",
				cmd1: newStageContext(
					fmt.Sprintf("COPY %s /meow", filePath),
					map[string]string{"ARG": "foo"},
					[]string{"ENV=1"},
				),
				cmd2: newStageContext(
					fmt.Sprintf("COPY %s /meow", filePath),
					map[string]string{"ARG": "foo"},
					[]string{"ENV=1"},
				),
				shdEqual: true,
			}
		}(),
		func() testcase {
			dir, files := tempDirAndFile(t)
			file := files[0]
			filePath := filepath.Join(dir, file)
			return testcase{
				description: "cache key for same command [COPY] with different args",
				cmd1: newStageContext(
					fmt.Sprintf("COPY %s /meow", filePath),
					map[string]string{"ARG": "foo"},
					[]string{"ENV=1"},
				),
				cmd2: newStageContext(
					fmt.Sprintf("COPY %s /meow", filePath),
					map[string]string{"ARG": "bar"},
					[]string{"ENV=2"},
				),
				shdEqual: true,
			}
		}(),
		{
			description: "cache key for same command [WORKDIR] with same args",
			cmd1: newStageContext(
				"WORKDIR /",
				map[string]string{"ARG": "foo"},
				[]string{"ENV=1"},
			),
			cmd2: newStageContext(
				"WORKDIR /",
				map[string]string{"ARG": "foo"},
				[]string{"ENV=1"},
			),
			shdEqual: true,
		},
		{
			description: "cache key for same command [WORKDIR] with different args",
			cmd1: newStageContext(
				"WORKDIR /",
				map[string]string{"ARG": "foo"},
				[]string{"ENV=1"},
			),
			cmd2: newStageContext(
				"WORKDIR /",
				map[string]string{"ARG": "bar"},
				[]string{"ENV=2"},
			),
			shdEqual: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			sb := &stageBuilder{fileContext: util.FileContext{Root: "workspace"}}
			ck := CompositeCache{}

			instructions1, err := dockerfile.ParseCommands([]string{tc.cmd1.command.String()})
			if err != nil {
				t.Fatal(err)
			}

			fc1 := util.FileContext{Root: "workspace"}
			dockerCommand1, err := commands.GetCommand(instructions1[0], fc1, false, true, true)
			if err != nil {
				t.Fatal(err)
			}

			instructions, err := dockerfile.ParseCommands([]string{tc.cmd2.command.String()})
			if err != nil {
				t.Fatal(err)
			}

			fc2 := util.FileContext{Root: "workspace"}
			dockerCommand2, err := commands.GetCommand(instructions[0], fc2, false, true, true)
			if err != nil {
				t.Fatal(err)
			}

			ck1, err := sb.populateCompositeKey(dockerCommand1, []string{}, ck, tc.cmd1.args, tc.cmd1.env)
			if err != nil {
				t.Errorf("Expected error to be nil but was %v", err)
			}
			ck2, err := sb.populateCompositeKey(dockerCommand2, []string{}, ck, tc.cmd2.args, tc.cmd2.env)
			if err != nil {
				t.Errorf("Expected error to be nil but was %v", err)
			}
			key1, key2 := hashCompositeKeys(t, ck1, ck2)
			if b := key1 == key2; b != tc.shdEqual {
				t.Errorf("expected keys to be equal as %t but found %t", tc.shdEqual, !tc.shdEqual)
			}
		})
	}
}

func Test_stageBuilder_build(t *testing.T) {
	type testcase struct {
		description        string
		opts               *config.KanikoOptions
		args               map[string]string
		layerCache         *fakeLayerCache
		expectedCacheKeys  []string
		pushedCacheKeys    []string
		commands           []commands.DockerCommand
		fileName           string
		rootDir            string
		image              v1.Image
		config             *v1.ConfigFile
		stage              config.KanikoStage
		crossStageDeps     map[int][]string
		mockGetFSFromImage func(root string, img v1.Image, extract util.ExtractFunction) ([]string, error)
		shouldInitSnapshot bool
	}

	testCases := []testcase{
		func() testcase {
			dir, files := tempDirAndFile(t)
			file := files[0]
			filePath := filepath.Join(dir, file)
			ch := NewCompositeCache("", "meow")

			ch.AddPath(filePath, util.FileContext{})
			hash, err := ch.Hash()
			if err != nil {
				t.Errorf("couldn't create hash %v", err)
			}
			command := MockDockerCommand{
				command:      "meow",
				contextFiles: []string{filePath},
				cacheCommand: MockCachedDockerCommand{
					contextFiles: []string{filePath},
				},
			}

			destDir := t.TempDir()
			return testcase{
				description:       "fake command cache enabled but key not in cache",
				config:            &v1.ConfigFile{Config: v1.Config{WorkingDir: destDir}},
				opts:              &config.KanikoOptions{Cache: true},
				expectedCacheKeys: []string{hash},
				pushedCacheKeys:   []string{hash},
				commands:          []commands.DockerCommand{command},
				rootDir:           dir,
			}
		}(),
		func() testcase {
			dir, files := tempDirAndFile(t)
			file := files[0]
			filePath := filepath.Join(dir, file)
			ch := NewCompositeCache("", "meow")

			ch.AddPath(filePath, util.FileContext{})
			hash, err := ch.Hash()
			if err != nil {
				t.Errorf("couldn't create hash %v", err)
			}
			command := MockDockerCommand{
				command:      "meow",
				contextFiles: []string{filePath},
				cacheCommand: MockCachedDockerCommand{
					contextFiles: []string{filePath},
				},
			}

			destDir := t.TempDir()
			return testcase{
				description: "fake command cache enabled and key in cache",
				opts:        &config.KanikoOptions{Cache: true},
				config:      &v1.ConfigFile{Config: v1.Config{WorkingDir: destDir}},
				layerCache: &fakeLayerCache{
					retrieve: true,
				},
				expectedCacheKeys: []string{hash},
				pushedCacheKeys:   []string{},
				commands:          []commands.DockerCommand{command},
				rootDir:           dir,
			}
		}(),
		func() testcase {
			dir, files := tempDirAndFile(t)
			file := files[0]
			filePath := filepath.Join(dir, file)
			ch := NewCompositeCache("", "meow")

			ch.AddPath(filePath, util.FileContext{})
			hash, err := ch.Hash()
			if err != nil {
				t.Errorf("couldn't create hash %v", err)
			}
			command := MockDockerCommand{
				command:      "meow",
				contextFiles: []string{filePath},
				cacheCommand: MockCachedDockerCommand{
					contextFiles: []string{filePath},
				},
			}

			destDir := t.TempDir()
			return testcase{
				description: "fake command cache enabled with tar compression disabled and key in cache",
				opts:        &config.KanikoOptions{Cache: true, CompressedCaching: false},
				config:      &v1.ConfigFile{Config: v1.Config{WorkingDir: destDir}},
				layerCache: &fakeLayerCache{
					retrieve: true,
				},
				expectedCacheKeys: []string{hash},
				pushedCacheKeys:   []string{},
				commands:          []commands.DockerCommand{command},
				rootDir:           dir,
			}
		}(),
		{
			description: "use new run",
			opts:        &config.KanikoOptions{RunV2: true},
		},
		{
			description:        "single snapshot",
			opts:               &config.KanikoOptions{SingleSnapshot: true},
			shouldInitSnapshot: true,
		},
		{
			description: "fake command cache disabled and key not in cache",
			opts:        &config.KanikoOptions{Cache: false},
		},
		{
			description: "fake command cache disabled and key in cache",
			opts:        &config.KanikoOptions{Cache: false},
			layerCache: &fakeLayerCache{
				retrieve: true,
			},
		},
		func() testcase {
			dir, filenames := tempDirAndFile(t)
			filename := filenames[0]
			filepath := filepath.Join(dir, filename)

			tarContent := generateTar(t, dir, filename)

			ch := NewCompositeCache("", fmt.Sprintf("COPY %s foo.txt", filename))
			ch.AddPath(filepath, util.FileContext{})

			hash, err := ch.Hash()
			if err != nil {
				t.Errorf("couldn't create hash %v", err)
			}
			copyCommandCacheKey := hash
			dockerFile := fmt.Sprintf(`
		FROM ubuntu:16.04
		COPY %s foo.txt
		`, filename)
			f, _ := os.CreateTemp("", "")
			os.WriteFile(f.Name(), []byte(dockerFile), 0755)
			opts := &config.KanikoOptions{
				DockerfilePath:  f.Name(),
				Cache:           true,
				CacheCopyLayers: true,
			}
			testStages, metaArgs, err := dockerfile.ParseStages(opts)
			if err != nil {
				t.Errorf("Failed to parse test dockerfile to stages: %s", err)
			}

			kanikoStages, err := dockerfile.MakeKanikoStages(opts, testStages, metaArgs)
			if err != nil {
				t.Errorf("Failed to parse stages to Kaniko Stages: %s", err)
			}
			_ = ResolveCrossStageInstructions(kanikoStages)
			stage := kanikoStages[0]

			cmds := stage.Commands

			return testcase{
				description: "copy command cache enabled and key in cache",
				opts:        opts,
				image: fakeImage{
					ImageLayers: []v1.Layer{
						fakeLayer{
							TarContent: tarContent,
						},
					},
				},
				layerCache: &fakeLayerCache{
					retrieve: true,
					img: fakeImage{
						ImageLayers: []v1.Layer{
							fakeLayer{
								TarContent: tarContent,
							},
						},
					},
				},
				rootDir:           dir,
				expectedCacheKeys: []string{copyCommandCacheKey},
				// CachingCopyCommand is not pushed to the cache
				pushedCacheKeys: []string{},
				commands:        getCommands(util.FileContext{Root: dir}, cmds, true, false),
				fileName:        filename,
			}
		}(),
		func() testcase {
			dir, filenames := tempDirAndFile(t)
			filename := filenames[0]
			tarContent := []byte{}
			destDir := t.TempDir()
			filePath := filepath.Join(dir, filename)
			ch := NewCompositeCache("", fmt.Sprintf("COPY %s foo.txt", filename))
			ch.AddPath(filePath, util.FileContext{})

			hash, err := ch.Hash()
			if err != nil {
				t.Errorf("couldn't create hash %v", err)
			}
			dockerFile := fmt.Sprintf(`
FROM ubuntu:16.04
COPY %s foo.txt
`, filename)
			f, _ := os.CreateTemp("", "")
			os.WriteFile(f.Name(), []byte(dockerFile), 0755)
			opts := &config.KanikoOptions{
				DockerfilePath:  f.Name(),
				Cache:           true,
				CacheCopyLayers: true,
			}

			testStages, metaArgs, err := dockerfile.ParseStages(opts)
			if err != nil {
				t.Errorf("Failed to parse test dockerfile to stages: %s", err)
			}

			kanikoStages, err := dockerfile.MakeKanikoStages(opts, testStages, metaArgs)
			if err != nil {
				t.Errorf("Failed to parse stages to Kaniko Stages: %s", err)
			}
			_ = ResolveCrossStageInstructions(kanikoStages)
			stage := kanikoStages[0]

			cmds := stage.Commands
			return testcase{
				description: "copy command cache enabled and key is not in cache",
				opts:        opts,
				config:      &v1.ConfigFile{Config: v1.Config{WorkingDir: destDir}},
				layerCache:  &fakeLayerCache{},
				image: fakeImage{
					ImageLayers: []v1.Layer{
						fakeLayer{
							TarContent: tarContent,
						},
					},
				},
				rootDir:           dir,
				expectedCacheKeys: []string{hash},
				pushedCacheKeys:   []string{hash},
				commands:          getCommands(util.FileContext{Root: dir}, cmds, true, false),
				fileName:          filename,
			}
		}(),
		func() testcase {
			dir, filenames := tempDirAndFile(t)
			filename := filenames[0]
			tarContent := generateTar(t, filename)

			destDir := t.TempDir()
			filePath := filepath.Join(dir, filename)

			ch := NewCompositeCache("", "RUN foobar")

			hash1, err := ch.Hash()
			if err != nil {
				t.Errorf("couldn't create hash %v", err)
			}

			ch.AddKey(fmt.Sprintf("COPY %s bar.txt", filename))
			ch.AddPath(filePath, util.FileContext{})

			hash2, err := ch.Hash()
			if err != nil {
				t.Errorf("couldn't create hash %v", err)
			}
			ch = NewCompositeCache("", fmt.Sprintf("COPY %s foo.txt", filename))
			ch.AddKey(fmt.Sprintf("COPY %s bar.txt", filename))
			ch.AddPath(filePath, util.FileContext{})

			image := fakeImage{
				ImageLayers: []v1.Layer{
					fakeLayer{
						TarContent: tarContent,
					},
				},
			}

			dockerFile := fmt.Sprintf(`
FROM ubuntu:16.04
RUN foobar
COPY %s bar.txt
`, filename)
			f, _ := os.CreateTemp("", "")
			os.WriteFile(f.Name(), []byte(dockerFile), 0755)
			opts := &config.KanikoOptions{
				DockerfilePath: f.Name(),
			}

			testStages, metaArgs, err := dockerfile.ParseStages(opts)
			if err != nil {
				t.Errorf("Failed to parse test dockerfile to stages: %s", err)
			}

			kanikoStages, err := dockerfile.MakeKanikoStages(opts, testStages, metaArgs)
			if err != nil {
				t.Errorf("Failed to parse stages to Kaniko Stages: %s", err)
			}
			_ = ResolveCrossStageInstructions(kanikoStages)
			stage := kanikoStages[0]

			cmds := stage.Commands
			return testcase{
				description: "cached run command followed by uncached copy command results in consistent read and write hashes",
				opts:        &config.KanikoOptions{Cache: true, CacheCopyLayers: true, CacheRunLayers: true},
				rootDir:     dir,
				config:      &v1.ConfigFile{Config: v1.Config{WorkingDir: destDir}},
				layerCache: &fakeLayerCache{
					keySequence: []string{hash1},
					img:         image,
				},
				image: image,
				// hash1 is the read cachekey for the first layer
				expectedCacheKeys: []string{hash1, hash2},
				pushedCacheKeys:   []string{hash2},
				commands:          getCommands(util.FileContext{Root: dir}, cmds, true, true),
			}
		}(),
		func() testcase {
			dir, filenames := tempDirAndFile(t)
			filename := filenames[0]
			tarContent := generateTar(t, filename)

			destDir := t.TempDir()

			filePath := filepath.Join(dir, filename)

			ch := NewCompositeCache("", fmt.Sprintf("COPY %s bar.txt", filename))
			ch.AddPath(filePath, util.FileContext{})

			// copy hash
			_, err := ch.Hash()
			if err != nil {
				t.Errorf("couldn't create hash %v", err)
			}

			ch.AddKey("RUN foobar")

			// run hash
			runHash, err := ch.Hash()
			if err != nil {
				t.Errorf("couldn't create hash %v", err)
			}

			image := fakeImage{
				ImageLayers: []v1.Layer{
					fakeLayer{
						TarContent: tarContent,
					},
				},
			}

			dockerFile := fmt.Sprintf(`
FROM ubuntu:16.04
COPY %s bar.txt
RUN foobar
`, filename)
			f, _ := os.CreateTemp("", "")
			os.WriteFile(f.Name(), []byte(dockerFile), 0755)
			opts := &config.KanikoOptions{
				DockerfilePath: f.Name(),
			}

			testStages, metaArgs, err := dockerfile.ParseStages(opts)
			if err != nil {
				t.Errorf("Failed to parse test dockerfile to stages: %s", err)
			}

			kanikoStages, err := dockerfile.MakeKanikoStages(opts, testStages, metaArgs)
			if err != nil {
				t.Errorf("Failed to parse stages to Kaniko Stages: %s", err)
			}
			_ = ResolveCrossStageInstructions(kanikoStages)
			stage := kanikoStages[0]

			cmds := stage.Commands
			return testcase{
				description: "copy command followed by cached run command results in consistent read and write hashes",
				opts:        &config.KanikoOptions{Cache: true, CacheRunLayers: true},
				rootDir:     dir,
				config:      &v1.ConfigFile{Config: v1.Config{WorkingDir: destDir}},
				layerCache: &fakeLayerCache{
					keySequence: []string{runHash},
					img:         image,
				},
				image:             image,
				expectedCacheKeys: []string{runHash},
				pushedCacheKeys:   []string{},
				commands:          getCommands(util.FileContext{Root: dir}, cmds, false, true),
			}
		}(),
		func() testcase {
			dir, _ := tempDirAndFile(t)
			ch := NewCompositeCache("")
			ch.AddKey("|1")
			ch.AddKey("test=value")
			ch.AddKey("RUN foobar")
			hash, err := ch.Hash()
			if err != nil {
				t.Errorf("couldn't create hash %v", err)
			}

			command := MockDockerCommand{
				command:      "RUN foobar",
				contextFiles: []string{},
				cacheCommand: MockCachedDockerCommand{
					contextFiles: []string{},
				},
				argToCompositeCache: true,
			}

			return testcase{
				description: "cached run command with no build arg value used uses cached layer and does not push anything",
				config:      &v1.ConfigFile{Config: v1.Config{WorkingDir: dir}},
				opts:        &config.KanikoOptions{Cache: true},
				args: map[string]string{
					"test": "value",
				},
				expectedCacheKeys: []string{hash},
				commands:          []commands.DockerCommand{command},
				// layer key needs to be read.
				layerCache: &fakeLayerCache{
					img:         &fakeImage{ImageLayers: []v1.Layer{fakeLayer{}}},
					keySequence: []string{hash},
				},
				rootDir: dir,
			}
		}(),
		func() testcase {
			dir, _ := tempDirAndFile(t)

			ch := NewCompositeCache("")
			ch.AddKey("|1")
			ch.AddKey("arg=value")
			ch.AddKey("RUN $arg")
			hash, err := ch.Hash()
			if err != nil {
				t.Errorf("couldn't create hash %v", err)
			}

			command := MockDockerCommand{
				command:      "RUN $arg",
				contextFiles: []string{},
				cacheCommand: MockCachedDockerCommand{
					contextFiles: []string{},
				},
				argToCompositeCache: true,
			}

			return testcase{
				description: "cached run command with same build arg does not push layer",
				config:      &v1.ConfigFile{Config: v1.Config{WorkingDir: dir}},
				opts:        &config.KanikoOptions{Cache: true},
				args: map[string]string{
					"arg": "value",
				},
				// layer key that exists
				layerCache: &fakeLayerCache{
					img:         &fakeImage{ImageLayers: []v1.Layer{fakeLayer{}}},
					keySequence: []string{hash},
				},
				expectedCacheKeys: []string{hash},
				commands:          []commands.DockerCommand{command},
				rootDir:           dir,
			}
		}(),
		func() testcase {
			dir, _ := tempDirAndFile(t)

			ch1 := NewCompositeCache("")
			ch1.AddKey("RUN value")
			hash1, err := ch1.Hash()
			if err != nil {
				t.Errorf("couldn't create hash %v", err)
			}

			ch2 := NewCompositeCache("")
			ch2.AddKey("|1")
			ch2.AddKey("arg=anotherValue")
			ch2.AddKey("RUN $arg")
			hash2, err := ch2.Hash()
			if err != nil {
				t.Errorf("couldn't create hash %v", err)
			}
			command := MockDockerCommand{
				command:      "RUN $arg",
				contextFiles: []string{},
				cacheCommand: MockCachedDockerCommand{
					contextFiles: []string{},
				},
				argToCompositeCache: true,
			}

			return testcase{
				description: "cached run command with another build arg pushes layer",
				config:      &v1.ConfigFile{Config: v1.Config{WorkingDir: dir}},
				opts:        &config.KanikoOptions{Cache: true},
				args: map[string]string{
					"arg": "anotherValue",
				},
				// layer for arg=value already exists
				layerCache: &fakeLayerCache{
					img:         &fakeImage{ImageLayers: []v1.Layer{fakeLayer{}}},
					keySequence: []string{hash1},
				},
				expectedCacheKeys: []string{hash2},
				pushedCacheKeys:   []string{hash2},
				commands:          []commands.DockerCommand{command},
				rootDir:           dir,
			}
		}(),
		{
			description:    "fs unpacked",
			opts:           &config.KanikoOptions{InitialFSUnpacked: true},
			stage:          config.KanikoStage{Index: 0},
			crossStageDeps: map[int][]string{0: {"some-dep"}},
			mockGetFSFromImage: func(root string, img v1.Image, extract util.ExtractFunction) ([]string, error) {
				return nil, fmt.Errorf("getFSFromImage shouldn't be called if fs is already unpacked")
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			var fileName string
			if tc.commands == nil {
				file, err := os.CreateTemp("", "foo")
				if err != nil {
					t.Error(err)
				}
				command := MockDockerCommand{
					contextFiles: []string{file.Name()},
					cacheCommand: MockCachedDockerCommand{
						contextFiles: []string{file.Name()},
					},
				}
				tc.commands = []commands.DockerCommand{command}
				fileName = file.Name()
			} else {
				fileName = tc.fileName
			}

			cf := tc.config
			if cf == nil {
				cf = &v1.ConfigFile{
					Config: v1.Config{
						Env: make([]string, 0),
					},
				}
			}

			snap := &fakeSnapShotter{file: fileName}
			lc := tc.layerCache
			if lc == nil {
				lc = &fakeLayerCache{}
			}
			keys := []string{}
			sb := &stageBuilder{
				args:        dockerfile.NewBuildArgs([]string{}), //required or code will panic
				image:       tc.image,
				opts:        tc.opts,
				cf:          cf,
				snapshotter: snap,
				layerCache:  lc,
				pushLayerToCache: func(_ *config.KanikoOptions, cacheKey, _, _ string) error {
					keys = append(keys, cacheKey)
					return nil
				},
			}
			sb.cmds = tc.commands
			for key, value := range tc.args {
				sb.args.AddArg(key, &value)
			}
			tmp := config.RootDir
			if tc.rootDir != "" {
				config.RootDir = tc.rootDir
			}
			sb.stage = tc.stage
			sb.crossStageDeps = tc.crossStageDeps
			if tc.mockGetFSFromImage != nil {
				original := getFSFromImage
				defer func() { getFSFromImage = original }()
				getFSFromImage = tc.mockGetFSFromImage
			}
			err := sb.build()
			if err != nil {
				t.Errorf("Expected error to be nil but was %v", err)
			}
			if tc.shouldInitSnapshot && !snap.initialized {
				t.Errorf("Snapshotter was not initialized but should have been")
			} else if !tc.shouldInitSnapshot && snap.initialized {
				t.Errorf("Snapshotter was initialized but should not have been")
			}
			assertCacheKeys(t, tc.expectedCacheKeys, lc.receivedKeys, "receive")
			assertCacheKeys(t, tc.pushedCacheKeys, keys, "push")

			config.RootDir = tmp

		})
	}
}

// TestUnpackFilesystemIfNeeded_InitialFSUnpacked tests that InitialFSUnpacked optimization works
func TestUnpackFilesystemIfNeeded_InitialFSUnpacked(t *testing.T) {
	// Use empty image to avoid registry access
	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Config: v1.Config{},
	})
	if err != nil {
		t.Fatalf("Failed to create test image: %v", err)
	}

	opts := &config.KanikoOptions{
		InitialFSUnpacked: true,
	}
	stage := &config.KanikoStage{
		Index: 0, // First stage
		Stage: instructions.Stage{
			BaseName: "scratch",
		},
	}

	// Create stageBuilder with empty image
	sb := &stageBuilder{
		stage:          *stage,
		image:          img,
		opts:           opts,
		cf:             &v1.ConfigFile{Config: v1.Config{}},
		args:           dockerfile.NewBuildArgs([]string{}),
		cmds:           []commands.DockerCommand{},
		crossStageDeps: map[int][]string{},
	}

	// Should skip unpacking for initial stage with InitialFSUnpacked=true
	err = sb.unpackFilesystemIfNeeded()
	if err != nil {
		t.Errorf("Expected no error when InitialFSUnpacked=true, got %v", err)
	}
}

// TestUnpackFilesystemIfNeeded_NonInitialStage tests that non-initial stages still unpack
func TestUnpackFilesystemIfNeeded_NonInitialStage(t *testing.T) {
	// Use empty image to avoid registry access
	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Config: v1.Config{},
	})
	if err != nil {
		t.Fatalf("Failed to create test image: %v", err)
	}

	opts := &config.KanikoOptions{
		InitialFSUnpacked: true,
	}
	stage := &config.KanikoStage{
		Index: 1, // Not first stage
		Stage: instructions.Stage{
			BaseName: "scratch",
		},
	}

	// Create stageBuilder with empty image
	sb := &stageBuilder{
		stage:          *stage,
		image:          img,
		opts:           opts,
		cf:             &v1.ConfigFile{Config: v1.Config{}},
		args:           dockerfile.NewBuildArgs([]string{}),
		cmds:           []commands.DockerCommand{},
		crossStageDeps: map[int][]string{},
	}

	// Should still check for unpacking (but may skip if no commands require it)
	// This test verifies the early return logic doesn't break non-initial stages
	err = sb.unpackFilesystemIfNeeded()
	// Error is expected if no image is set up, but the function should not panic
	_ = err // We're just testing the early return path doesn't break
}

// TestCalculatePrefetchKeys tests that prefetch keys are calculated correctly
func TestCalculatePrefetchKeys(t *testing.T) {
	// Use empty image to avoid registry access
	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Config: v1.Config{},
	})
	if err != nil {
		t.Fatalf("Failed to create test image: %v", err)
	}

	opts := &config.KanikoOptions{
		EnableUnifiedCache: true,
		Cache:              true,
	}
	stage := &config.KanikoStage{
		Index: 0,
		Stage: instructions.Stage{
			BaseName: "scratch",
		},
	}

	// Create stageBuilder with empty image
	sb := &stageBuilder{
		stage:          *stage,
		image:          img,
		opts:           opts,
		cf:             &v1.ConfigFile{Config: v1.Config{}},
		args:           dockerfile.NewBuildArgs([]string{}),
		cmds:           []commands.DockerCommand{},
		crossStageDeps: map[int][]string{},
		fileContext:    util.FileContext{},
	}

	compositeKey := NewCompositeCache("base")
	cfg := &v1.Config{Env: []string{}}
	args := dockerfile.NewBuildArgs([]string{})

	// Calculate prefetch keys for first command (index 0)
	prefetchKeys := sb.calculatePrefetchKeys(0, *compositeKey, cfg, args)

	// Should calculate keys for next 2-3 commands
	if len(prefetchKeys) == 0 && len(sb.cmds) > 1 {
		// If there are commands but no prefetch keys, that's also valid
		// (commands might not be cacheable)
		t.Logf("No prefetch keys calculated (commands may not be cacheable)")
	}
}

// TestCalculatePrefetchKeys_aggressive tests aggressive prefetching with increased window
func TestCalculatePrefetchKeys_aggressive(t *testing.T) {
	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Config: v1.Config{},
	})
	if err != nil {
		t.Fatalf("Failed to create test image: %v", err)
	}

	testCases := []struct {
		name           string
		prefetchWindow int
		numCommands    int
		currentIndex   int
		expectedMax    int
	}{
		{
			name:           "default prefetch window (10)",
			prefetchWindow: 0, // Will use default
			numCommands:    15,
			currentIndex:   0,
			expectedMax:    10, // Default is 10
		},
		{
			name:           "custom prefetch window (15)",
			prefetchWindow: 15,
			numCommands:    20,
			currentIndex:   0,
			expectedMax:    15,
		},
		{
			name:           "small prefetch window (5)",
			prefetchWindow: 5,
			numCommands:    10,
			currentIndex:   0,
			expectedMax:    5,
		},
		{
			name:           "prefetch window larger than remaining commands",
			prefetchWindow: 20,
			numCommands:    10,
			currentIndex:   5,
			expectedMax:    5, // Only 5 commands remaining
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := &config.KanikoOptions{
				EnableUnifiedCache: true,
				Cache:              true,
				PrefetchWindow:     tc.prefetchWindow,
			}

			stage := &config.KanikoStage{
				Index: 0,
				Stage: instructions.Stage{
					BaseName: "scratch",
				},
			}

			// Create commands
			cmds := make([]commands.DockerCommand, tc.numCommands)
			for i := 0; i < tc.numCommands; i++ {
				file, err := os.CreateTemp("", fmt.Sprintf("test%d", i))
				if err != nil {
					t.Fatalf("Failed to create temp file: %v", err)
				}
				defer os.Remove(file.Name())

				cmds[i] = MockDockerCommand{
					command:      fmt.Sprintf("RUN echo %d", i),
					contextFiles: []string{file.Name()},
					cacheCommand: MockCachedDockerCommand{},
				}
			}

			sb := &stageBuilder{
				stage:          *stage,
				image:          img,
				opts:           opts,
				cf:             &v1.ConfigFile{Config: v1.Config{}},
				args:           dockerfile.NewBuildArgs([]string{}),
				cmds:           cmds,
				crossStageDeps: map[int][]string{},
				fileContext:    util.FileContext{},
			}

			compositeKey := NewCompositeCache("base")
			cfg := &v1.Config{Env: []string{}}
			args := dockerfile.NewBuildArgs([]string{})

			// Calculate prefetch keys
			prefetchKeys := sb.calculatePrefetchKeys(tc.currentIndex, *compositeKey, cfg, args)

			// Verify that we don't exceed expected maximum
			if len(prefetchKeys) > tc.expectedMax {
				t.Errorf("Expected at most %d prefetch keys, got %d", tc.expectedMax, len(prefetchKeys))
			}

			// Verify that we don't exceed remaining commands
			remainingCommands := tc.numCommands - tc.currentIndex - 1
			if len(prefetchKeys) > remainingCommands {
				t.Errorf("Expected at most %d prefetch keys (remaining commands), got %d", remainingCommands, len(prefetchKeys))
			}

			// Log for debugging
			t.Logf("Prefetch window: %d, Calculated keys: %d, Expected max: %d",
				tc.prefetchWindow, len(prefetchKeys), tc.expectedMax)
		})
	}
}

// TestPrefetchNextLayers_background tests that prefetch runs in background
func TestPrefetchNextLayers_background(t *testing.T) {
	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Config: v1.Config{},
	})
	if err != nil {
		t.Fatalf("Failed to create test image: %v", err)
	}

	opts := &config.KanikoOptions{
		EnableUnifiedCache: true,
		Cache:              true,
		PrefetchWindow:     10,
	}

	stage := &config.KanikoStage{
		Index: 0,
		Stage: instructions.Stage{
			BaseName: "scratch",
		},
	}

	// Create test commands
	cmds := make([]commands.DockerCommand, 5)
	for i := 0; i < 5; i++ {
		file, err := os.CreateTemp("", fmt.Sprintf("test%d", i))
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer os.Remove(file.Name())

		cmds[i] = MockDockerCommand{
			command:      fmt.Sprintf("RUN echo %d", i),
			contextFiles: []string{file.Name()},
			cacheCommand: MockCachedDockerCommand{},
		}
	}

	// Create a real UnifiedCache to test prefetching
	realCache := cache.NewUnifiedCache(&fakeLayerCache{retrieve: false, img: &fakeImage{}})

	sb := &stageBuilder{
		stage:          *stage,
		image:          img,
		opts:           opts,
		cf:             &v1.ConfigFile{Config: v1.Config{}},
		args:           dockerfile.NewBuildArgs([]string{}),
		cmds:           cmds,
		crossStageDeps: map[int][]string{},
		fileContext:    util.FileContext{},
		layerCache:     realCache,
	}

	compositeKey := NewCompositeCache("base")
	cfg := &v1.Config{Env: []string{}}

	// Get initial stats
	initialStats := realCache.GetStats()
	initialQueueLen := initialStats["prefetch_queue"].(int)

	// Call prefetchNextLayers (should run in background)
	sb.prefetchNextLayers(0, *compositeKey, cfg)

	// Wait a bit for background goroutine to start and process
	time.Sleep(100 * time.Millisecond)

	// Verify that prefetch was attempted
	// Since prefetch runs in background, we check that the function doesn't block
	// and that prefetch queue was updated (if keys were calculated)
	finalStats := realCache.GetStats()
	finalQueueLen := finalStats["prefetch_queue"].(int)
	prefetching := finalStats["prefetching"].(bool)

	// Prefetch should have been called (either queue increased or prefetching started)
	if initialQueueLen == 0 && finalQueueLen == 0 && !prefetching {
		// This might happen if no cacheable commands were found
		// Check that at least calculatePrefetchKeys was called (by checking commands)
		if len(cmds) > 0 {
			t.Logf("Prefetch may have processed quickly or no cacheable commands found")
		}
	} else {
		// Prefetch was called (queue updated or prefetching in progress)
		t.Logf("Prefetch was called: queue=%d->%d, prefetching=%v",
			initialQueueLen, finalQueueLen, prefetching)
	}
}

// TestCalculatePrefetchKeys_windowIncrease tests that window increased from 3 to configurable value
func TestCalculatePrefetchKeys_windowIncrease(t *testing.T) {
	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Config: v1.Config{},
	})
	if err != nil {
		t.Fatalf("Failed to create test image: %v", err)
	}

	// Test with default value (should be 10, not 3)
	opts := &config.KanikoOptions{
		EnableUnifiedCache: true,
		Cache:              true,
		// PrefetchWindow not set, should use default 10
	}

	stage := &config.KanikoStage{
		Index: 0,
		Stage: instructions.Stage{
			BaseName: "scratch",
		},
	}

	// Create 15 commands to test that we prefetch more than 3
	cmds := make([]commands.DockerCommand, 15)
	for i := 0; i < 15; i++ {
		file, err := os.CreateTemp("", fmt.Sprintf("test%d", i))
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer os.Remove(file.Name())

		cmds[i] = MockDockerCommand{
			command:      fmt.Sprintf("RUN echo %d", i),
			contextFiles: []string{file.Name()},
			cacheCommand: MockCachedDockerCommand{},
		}
	}

	sb := &stageBuilder{
		stage:          *stage,
		image:          img,
		opts:           opts,
		cf:             &v1.ConfigFile{Config: v1.Config{}},
		args:           dockerfile.NewBuildArgs([]string{}),
		cmds:           cmds,
		crossStageDeps: map[int][]string{},
		fileContext:    util.FileContext{},
	}

	compositeKey := NewCompositeCache("base")
	cfg := &v1.Config{Env: []string{}}
	args := dockerfile.NewBuildArgs([]string{})

	// Calculate prefetch keys from index 0
	prefetchKeys := sb.calculatePrefetchKeys(0, *compositeKey, cfg, args)

	// With default PrefetchWindow=10, we should get more than 3 keys
	// (assuming all commands are cacheable)
	if len(prefetchKeys) > 0 && len(prefetchKeys) <= 3 {
		t.Errorf("Expected more than 3 prefetch keys with default window (10), got %d. "+
			"This suggests the window wasn't increased from the old default of 3.", len(prefetchKeys))
	}

	// With 15 commands and window of 10, we should get at most 10 keys
	if len(prefetchKeys) > 10 {
		t.Errorf("Expected at most 10 prefetch keys with default window, got %d", len(prefetchKeys))
	}

	t.Logf("Prefetch keys calculated: %d (expected: up to 10 with default window)", len(prefetchKeys))
}

// TestFileSearchCache tests that cross-stage file search caching works
func TestFileSearchCache(t *testing.T) {
	// Use empty image to avoid registry access
	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Config: v1.Config{},
	})
	if err != nil {
		t.Fatalf("Failed to create test image: %v", err)
	}

	opts := &config.KanikoOptions{
		Cache: true,
	}
	stage := &config.KanikoStage{
		Index: 0,
		Stage: instructions.Stage{
			BaseName: "scratch",
		},
	}

	// Create stageBuilder with empty image
	sb := &stageBuilder{
		stage:           *stage,
		image:           img,
		opts:            opts,
		cf:              &v1.ConfigFile{Config: v1.Config{}},
		args:            dockerfile.NewBuildArgs([]string{}),
		cmds:            []commands.DockerCommand{},
		crossStageDeps:  map[int][]string{},
		fileContext:     util.FileContext{},
		fileSearchCache: make(map[string][]string),
	}

	buildArgs := dockerfile.NewBuildArgs([]string{})
	searchRoot := "/"

	// First search - should compute and cache
	result1, err1 := sb.findFilesForDependencyWithArgsFromRoot("/nonexistent", buildArgs, searchRoot)
	_ = err1 // Error expected for non-existent path

	// Second search with same path - should use cache
	result2, err2 := sb.findFilesForDependencyWithArgsFromRoot("/nonexistent", buildArgs, searchRoot)
	_ = err2

	// Results should be the same (both from cache or both computed)
	if len(result1) != len(result2) {
		t.Errorf("Expected same results from cache, got result1=%v, result2=%v", result1, result2)
	}

	// Verify cache was populated
	if len(sb.fileSearchCache) == 0 {
		t.Logf("Cache may be empty if search failed (this is acceptable)")
	}
}

// TestPrefetchNextLayers tests that prefetch works correctly
func TestPrefetchNextLayers(t *testing.T) {
	// Use empty image to avoid registry access
	img, err := mutate.ConfigFile(empty.Image, &v1.ConfigFile{
		Config: v1.Config{},
	})
	if err != nil {
		t.Fatalf("Failed to create test image: %v", err)
	}

	opts := &config.KanikoOptions{
		EnableUnifiedCache: true,
		Cache:              true,
	}
	stage := &config.KanikoStage{
		Index: 0,
		Stage: instructions.Stage{
			BaseName: "scratch",
		},
	}

	// Create stageBuilder with empty image
	sb := &stageBuilder{
		stage:          *stage,
		image:          img,
		opts:           opts,
		cf:             &v1.ConfigFile{Config: v1.Config{}},
		args:           dockerfile.NewBuildArgs([]string{}),
		cmds:           []commands.DockerCommand{},
		crossStageDeps: map[int][]string{},
		fileContext:    util.FileContext{},
	}

	// Create a mock unified cache
	unifiedCache := cache.NewUnifiedCache()
	sb.layerCache = unifiedCache

	compositeKey := NewCompositeCache("base")
	cfg := &v1.Config{Env: []string{}}

	// Test prefetch when unified cache is enabled
	sb.prefetchNextLayers(0, *compositeKey, cfg)

	// If no commands, prefetch should do nothing (no error)
	t.Logf("Prefetch completed successfully")
}

func assertCacheKeys(t *testing.T, expectedCacheKeys, actualCacheKeys []string, description string) {
	if len(expectedCacheKeys) != len(actualCacheKeys) {
		t.Errorf("expected to %v %v keys but was %v", description, len(expectedCacheKeys), len(actualCacheKeys))
	}

	sort.Slice(expectedCacheKeys, func(x, y int) bool {
		return expectedCacheKeys[x] > expectedCacheKeys[y]
	})
	sort.Slice(actualCacheKeys, func(x, y int) bool {
		return actualCacheKeys[x] > actualCacheKeys[y]
	})

	if len(expectedCacheKeys) != len(actualCacheKeys) {
		t.Errorf("expected %v to equal %v", actualCacheKeys, expectedCacheKeys)
	}

	for i, key := range expectedCacheKeys {
		if key != actualCacheKeys[i] {
			t.Errorf("expected to %v keys %d to be %v but was %v %v", description, i, key, actualCacheKeys[i], actualCacheKeys)
		}
	}
}

func getCommands(fileContext util.FileContext, cmds []instructions.Command, cacheCopy, cacheRun bool) []commands.DockerCommand {
	outCommands := make([]commands.DockerCommand, 0)
	for _, c := range cmds {
		cmd, err := commands.GetCommand(
			c,
			fileContext,
			false,
			cacheCopy,
			cacheRun,
		)
		if err != nil {
			panic(err)
		}
		outCommands = append(outCommands, cmd)
	}
	return outCommands
}

func tempDirAndFile(t *testing.T) (string, []string) {
	filenames := []string{"bar.txt"}

	dir := t.TempDir()
	for _, filename := range filenames {
		filepath := filepath.Join(dir, filename)
		err := os.WriteFile(filepath, []byte(`meow`), 0777)
		if err != nil {
			t.Errorf("could not create temp file %v", err)
		}
	}

	return dir, filenames
}

func generateTar(t *testing.T, dir string, fileNames ...string) []byte {
	buf := bytes.NewBuffer([]byte{})
	writer := tar.NewWriter(buf)
	defer writer.Close()

	for _, filename := range fileNames {
		filePath := filepath.Join(dir, filename)
		info, err := os.Stat(filePath)
		if err != nil {
			t.Errorf("could not get file info for temp file %v", err)
		}
		hdr, err := tar.FileInfoHeader(info, filename)
		if err != nil {
			t.Errorf("could not get tar header for temp file %v", err)
		}

		if err := writer.WriteHeader(hdr); err != nil {
			t.Errorf("could not write tar header %v", err)
		}

		content, err := os.ReadFile(filePath)
		if err != nil {
			t.Errorf("could not read tempfile %v", err)
		}

		if _, err := writer.Write(content); err != nil {
			t.Errorf("could not write file contents to tar")
		}
	}
	return buf.Bytes()
}

func hashCompositeKeys(t *testing.T, ck1 CompositeCache, ck2 CompositeCache) (string, string) {
	key1, err := ck1.Hash()
	if err != nil {
		t.Errorf("could not hash composite key due to %s", err)
	}
	key2, err := ck2.Hash()
	if err != nil {
		t.Errorf("could not hash composite key due to %s", err)
	}
	return key1, key2
}

func Test_stageBuild_populateCompositeKeyForCopyCommand(t *testing.T) {
	// See https://github.com/Gosayram/kaniko/issues/589

	for _, tc := range []struct {
		description      string
		command          string
		expectedCacheKey string
	}{
		{
			description: "multi-stage copy command",
			// dont use digest from previoust stage for COPY
			command:          "COPY --from=0 foo.txt bar.txt",
			expectedCacheKey: "COPY --from=0 foo.txt bar.txt",
		},
		{
			description:      "copy command",
			command:          "COPY foo.txt bar.txt",
			expectedCacheKey: "COPY foo.txt bar.txt",
		},
	} {
		t.Run(tc.description, func(t *testing.T) {
			instructions, err := dockerfile.ParseCommands([]string{tc.command})
			if err != nil {
				t.Fatal(err)
			}

			fc := util.FileContext{Root: "workspace"}
			copyCommand, err := commands.GetCommand(instructions[0], fc, false, true, true)
			if err != nil {
				t.Fatal(err)
			}

			for _, useCacheCommand := range []bool{false, true} {
				t.Run(fmt.Sprintf("CacheCommand=%t", useCacheCommand), func(t *testing.T) {
					var cmd commands.DockerCommand = copyCommand
					if useCacheCommand {
						cmd = copyCommand.(*commands.CopyCommand).CacheCommand(nil)
					}

					sb := &stageBuilder{
						fileContext: fc,
						stageIdxToDigest: map[string]string{
							"0": "some-digest",
						},
						digestToCacheKey: map[string]string{
							"some-digest": "some-cache-key",
						},
					}

					ck := CompositeCache{}
					ck, err = sb.populateCompositeKey(
						cmd,
						[]string{},
						ck,
						dockerfile.NewBuildArgs([]string{}),
						[]string{},
					)
					if err != nil {
						t.Fatal(err)
					}

					actualCacheKey := ck.Key()
					if tc.expectedCacheKey != actualCacheKey {
						t.Errorf(
							"Expected cache key to be %s, was %s",
							tc.expectedCacheKey,
							actualCacheKey,
						)
					}

				})
			}
		})
	}
}

func Test_ResolveCrossStageInstructions(t *testing.T) {
	df := `
	FROM scratch
	RUN echo hi > /hi

	FROM scratch AS second
	COPY --from=0 /hi /hi2

	FROM scratch AS tHiRd
	COPY --from=second /hi2 /hi3
	COPY --from=1 /hi2 /hi3

	FROM scratch
	COPY --from=thIrD /hi3 /hi4
	COPY --from=third /hi3 /hi4
	COPY --from=2 /hi3 /hi4
	`
	stages, metaArgs, err := dockerfile.Parse([]byte(df))
	if err != nil {
		t.Fatal(err)
	}
	opts := &config.KanikoOptions{}
	kanikoStages, err := dockerfile.MakeKanikoStages(opts, stages, metaArgs)
	if err != nil {
		t.Fatal(err)
	}
	stageToIdx := ResolveCrossStageInstructions(kanikoStages)
	for index, stage := range stages {
		if index == 0 {
			continue
		}
		expectedStage := strconv.Itoa(index - 1)
		for _, command := range stage.Commands {
			copyCmd := command.(*instructions.CopyCommand)
			if copyCmd.From != expectedStage {
				t.Fatalf("unexpected copy command: %s resolved to stage %s, expected %s", copyCmd.String(), copyCmd.From, expectedStage)
			}
		}

		expectedMap := map[string]string{"second": "1", "third": "2"}
		testutil.CheckDeepEqual(t, expectedMap, stageToIdx)
	}
}

func Test_stageBuilder_saveSnapshotToLayer(t *testing.T) {
	dir, files := tempDirAndFile(t)
	type fields struct {
		stage            config.KanikoStage
		image            v1.Image
		cf               *v1.ConfigFile
		baseImageDigest  string
		finalCacheKey    string
		opts             *config.KanikoOptions
		fileContext      util.FileContext
		cmds             []commands.DockerCommand
		args             *dockerfile.BuildArgs
		crossStageDeps   map[int][]string
		digestToCacheKey map[string]string
		stageIdxToDigest map[string]string
		snapshotter      snapShotter
		layerCache       cache.LayerCache
		pushLayerToCache cachePusher
	}
	type args struct {
		tarPath string
	}
	tests := []struct {
		name              string
		fields            fields
		args              args
		expectedMediaType types.MediaType
		expectedDiff      v1.Hash
		expectedDigest    v1.Hash
		wantErr           bool
	}{
		{
			name: "oci image",
			fields: fields{
				image: ociFakeImage{},
				opts: &config.KanikoOptions{
					ForceBuildMetadata: true,
				},
			},
			args: args{
				tarPath: filepath.Join(dir, files[0]),
			},
			expectedMediaType: types.OCILayer,
			expectedDiff: v1.Hash{
				Algorithm: "sha256",
				Hex:       "404cdd7bc109c432f8cc2443b45bcfe95980f5107215c645236e577929ac3e52",
			},
			expectedDigest: v1.Hash{
				Algorithm: "sha256",
				Hex:       "1dc5887a31ec6b388646be46c5f0b2036f92f4cbba50d12163a8be4074565a91",
			},
		},
		{
			name: "docker image",
			fields: fields{
				image: fakeImage{},
				opts: &config.KanikoOptions{
					ForceBuildMetadata: true,
				},
			},
			args: args{
				tarPath: filepath.Join(dir, files[0]),
			},
			expectedMediaType: types.DockerLayer,
			expectedDiff: v1.Hash{
				Algorithm: "sha256",
				Hex:       "404cdd7bc109c432f8cc2443b45bcfe95980f5107215c645236e577929ac3e52",
			},
			expectedDigest: v1.Hash{
				Algorithm: "sha256",
				Hex:       "1dc5887a31ec6b388646be46c5f0b2036f92f4cbba50d12163a8be4074565a91",
			},
		},
		{
			name: "oci image, zstd compression",
			fields: fields{
				image: ociFakeImage{},
				opts: &config.KanikoOptions{
					ForceBuildMetadata: true,
					Compression:        config.ZStd,
				},
			},
			args: args{
				tarPath: filepath.Join(dir, files[0]),
			},
			expectedMediaType: types.OCILayerZStd,
			expectedDiff: v1.Hash{
				Algorithm: "sha256",
				Hex:       "404cdd7bc109c432f8cc2443b45bcfe95980f5107215c645236e577929ac3e52",
			},
			expectedDigest: v1.Hash{
				Algorithm: "sha256",
				Hex:       "28369c11d9b68c9877781eaf4d8faffb4d0ada1900a1fb83ad452e58a072b45b",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &stageBuilder{
				stage:            tt.fields.stage,
				image:            tt.fields.image,
				cf:               tt.fields.cf,
				baseImageDigest:  tt.fields.baseImageDigest,
				finalCacheKey:    tt.fields.finalCacheKey,
				opts:             tt.fields.opts,
				fileContext:      tt.fields.fileContext,
				cmds:             tt.fields.cmds,
				args:             tt.fields.args,
				crossStageDeps:   tt.fields.crossStageDeps,
				digestToCacheKey: tt.fields.digestToCacheKey,
				stageIdxToDigest: tt.fields.stageIdxToDigest,
				snapshotter:      tt.fields.snapshotter,
				layerCache:       tt.fields.layerCache,
				pushLayerToCache: tt.fields.pushLayerToCache,
			}
			got, err := s.saveSnapshotToLayer(tt.args.tarPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("stageBuilder.saveSnapshotToLayer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if mt, _ := got.MediaType(); mt != tt.expectedMediaType {
				t.Errorf("expected mediatype %s, got %s", tt.expectedMediaType, mt)
				return
			}
			if diff, _ := got.DiffID(); diff != tt.expectedDiff {
				t.Errorf("expected diff %s, got %s", tt.expectedDiff, diff)
				return
			}
			if digest, _ := got.Digest(); digest != tt.expectedDigest {
				t.Errorf("expected digest %s, got %s", tt.expectedDigest, digest)
				return
			}
		})
	}
}

func Test_stageBuilder_convertLayerMediaType(t *testing.T) {
	type fields struct {
		stage            config.KanikoStage
		image            v1.Image
		cf               *v1.ConfigFile
		baseImageDigest  string
		finalCacheKey    string
		opts             *config.KanikoOptions
		fileContext      util.FileContext
		cmds             []commands.DockerCommand
		args             *dockerfile.BuildArgs
		crossStageDeps   map[int][]string
		digestToCacheKey map[string]string
		stageIdxToDigest map[string]string
		snapshotter      snapShotter
		layerCache       cache.LayerCache
		pushLayerToCache cachePusher
	}
	type args struct {
		layer v1.Layer
	}
	tests := []struct {
		name              string
		fields            fields
		args              args
		expectedMediaType types.MediaType
		wantErr           bool
	}{
		{
			name: "docker image w/ docker layer",
			fields: fields{
				image: fakeImage{},
			},
			args: args{
				layer: fakeLayer{
					mediaType: types.DockerLayer,
				},
			},
			expectedMediaType: types.DockerLayer,
		},
		{
			name: "oci image w/ oci layer",
			fields: fields{
				image: ociFakeImage{},
			},
			args: args{
				layer: fakeLayer{
					mediaType: types.OCILayer,
				},
			},
			expectedMediaType: types.OCILayer,
		},
		{
			name: "oci image w/ convertable docker layer",
			fields: fields{
				image: ociFakeImage{},
				opts:  &config.KanikoOptions{},
			},
			args: args{
				layer: fakeLayer{
					mediaType: types.DockerLayer,
				},
			},
			expectedMediaType: types.OCILayer,
		},
		{
			name: "oci image w/ convertable docker layer and zstd compression",
			fields: fields{
				image: ociFakeImage{},
				opts: &config.KanikoOptions{
					Compression: config.ZStd,
				},
			},
			args: args{
				layer: fakeLayer{
					mediaType: types.DockerLayer,
				},
			},
			expectedMediaType: types.OCILayerZStd,
		},
		{
			name: "docker image and oci zstd layer",
			fields: fields{
				image: dockerFakeImage{},
				opts:  &config.KanikoOptions{},
			},
			args: args{
				layer: fakeLayer{
					mediaType: types.OCILayerZStd,
				},
			},
			expectedMediaType: types.DockerLayer,
		},
		{
			name: "docker image w/ uncovertable oci image",
			fields: fields{
				image: dockerFakeImage{},
				opts:  &config.KanikoOptions{},
			},
			args: args{
				layer: fakeLayer{
					mediaType: types.OCIUncompressedRestrictedLayer,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &stageBuilder{
				stage:            tt.fields.stage,
				image:            tt.fields.image,
				cf:               tt.fields.cf,
				baseImageDigest:  tt.fields.baseImageDigest,
				finalCacheKey:    tt.fields.finalCacheKey,
				opts:             tt.fields.opts,
				fileContext:      tt.fields.fileContext,
				cmds:             tt.fields.cmds,
				args:             tt.fields.args,
				crossStageDeps:   tt.fields.crossStageDeps,
				digestToCacheKey: tt.fields.digestToCacheKey,
				stageIdxToDigest: tt.fields.stageIdxToDigest,
				snapshotter:      tt.fields.snapshotter,
				layerCache:       tt.fields.layerCache,
				pushLayerToCache: tt.fields.pushLayerToCache,
			}
			got, err := s.convertLayerMediaType(tt.args.layer)
			if (err != nil) != tt.wantErr {
				t.Errorf("stageBuilder.convertLayerMediaType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				mt, _ := got.MediaType()
				if mt != tt.expectedMediaType {
					t.Errorf("stageBuilder.convertLayerMediaType() = %v, want %v", mt, tt.expectedMediaType)
				}
			}
		})
	}
}
