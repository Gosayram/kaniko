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

// Package main provides the entry point for the Kaniko executor
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Gosayram/kaniko/cmd/executor/cmd"
	"github.com/Gosayram/kaniko/internal/version"
	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/util"

	"github.com/google/slowjam/pkg/stacklog"
)

func main() {
	// Initialize configuration
	config.Initialize()
	util.Initialize()

	// Handle --version flag before cobra initialization
	showVersion := flag.Bool("version", false, "Print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("Kaniko Executor\n")
		fmt.Printf("Version: %s\n", version.Version)
		fmt.Printf("Commit: %s\n", version.Commit)
		fmt.Printf("Build date: %s\n", version.Date)
		os.Exit(0)
	}

	s := stacklog.MustStartFromEnv("STACKLOG_PATH")

	if err := cmd.RootCmd.Execute(); err != nil {
		s.Stop()
		os.Exit(1)
	}
}
