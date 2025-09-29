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

package dockerfile

import (
	"strings"

	d "github.com/docker/docker/builder/dockerfile"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"
)

type BuildArgs struct {
	d.BuildArgs
	allowedArgs     map[string]*string
	allowedMetaArgs map[string]*string
}

func NewBuildArgs(args []string) *BuildArgs {
	argsFromOptions := make(map[string]*string)
	for _, a := range args {
		s := strings.SplitN(a, "=", 2)
		if len(s) == 1 {
			argsFromOptions[s[0]] = nil
		} else {
			argsFromOptions[s[0]] = &s[1]
		}
	}
	return &BuildArgs{
		BuildArgs:       *d.NewBuildArgs(argsFromOptions),
		allowedArgs:     argsFromOptions,
		allowedMetaArgs: make(map[string]*string),
	}
}

func (b *BuildArgs) Clone() *BuildArgs {
	clone := b.BuildArgs.Clone()
	allowedArgsClone := make(map[string]*string)
	for k, v := range b.allowedArgs {
		if v != nil {
			sv := *v
			cloneV := &sv
			allowedArgsClone[k] = cloneV
		} else {
			allowedArgsClone[k] = nil
		}
	}
	allowedMetaArgsClone := make(map[string]*string)
	for k, v := range b.allowedMetaArgs {
		if v != nil {
			sv := *v
			cloneV := &sv
			allowedMetaArgsClone[k] = cloneV
		} else {
			allowedMetaArgsClone[k] = nil
		}
	}
	return &BuildArgs{
		BuildArgs:       *clone,
		allowedArgs:     allowedArgsClone,
		allowedMetaArgs: allowedMetaArgsClone,
	}
}

// ReplacementEnvs returns a list of filtered environment variables
func (b *BuildArgs) ReplacementEnvs(envs []string) []string {
	// Ensure that we operate on a new array and do not modify the underlying array
	resultEnv := make([]string, len(envs))
	copy(resultEnv, envs)
	filtered := b.FilterAllowed(envs)
	// Disable makezero linter, since the previous make is paired with a same sized copy
	return append(resultEnv, filtered...) //nolint:makezero
}

// AddMetaArgs adds the supplied args map to b's allowedMetaArgs
func (b *BuildArgs) AddMetaArgs(metaArgs []instructions.ArgCommand) {
	for _, marg := range metaArgs {
		for _, arg := range marg.Args {
			v := arg.Value
			b.AddMetaArg(arg.Key, v)
		}
	}
}

func (b *BuildArgs) FilterAllowed(envs []string) []string {
	var filtered []string
	for _, env := range envs {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) >= 1 {
			if _, ok := b.allowedArgs[parts[0]]; ok {
				filtered = append(filtered, env)
			}
		}
	}
	return filtered
}

func (b *BuildArgs) AddMetaArg(key string, value *string) {
	b.allowedMetaArgs[key] = value
}
