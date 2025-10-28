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
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/moby/buildkit/frontend/dockerfile/instructions"

	"github.com/Gosayram/kaniko/pkg/dockerfile"
	"github.com/Gosayram/kaniko/pkg/rootless"
)

// UserCommand implements the Dockerfile USER instruction
type UserCommand struct {
	BaseCommand
	cmd *instructions.UserCommand
}

// ExecuteCommand processes the USER instruction by setting the user/group for subsequent commands
func (r *UserCommand) ExecuteCommand(config *v1.Config, buildArgs *dockerfile.BuildArgs) error {
	// Rootless: automatic permission validation before execution
	rootlessManager := rootless.GetManager()
	if rootlessManager.IsRootlessMode() {
		if err := rootlessManager.ValidateCommandPermissions("USER"); err != nil {
			return err
		}
	}

	// Use common helper for setup
	helper := NewCommonCommandHelper()
	helper.LogCommandExecution("USER")

	// Set the user in config first for resolution
	config.User = r.cmd.User

	// Resolve user using common helper
	userStr, err := helper.ResolveUserFromConfig(config, buildArgs)
	if err != nil {
		return err
	}

	config.User = userStr

	// Rootless: update target user in rootless manager
	if err := rootlessManager.ValidateTargetUser(userStr); err != nil {
		return err
	}

	return nil
}

func (r *UserCommand) String() string {
	return r.cmd.String()
}
