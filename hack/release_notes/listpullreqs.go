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

// Package main provides a tool to list pull requests between two versions in changelog format.
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/go-github/github"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

var (
	token   string
	fromTag string
	toTag   string
)

var rootCmd = &cobra.Command{
	Use:        "listpullreqs fromTag toTag",
	Short:      "Lists pull requests between two versions in our changelog markdown format",
	ArgAliases: []string{"fromTag", "toTag"},
	Run: func(_ *cobra.Command, _ []string) {
		printPullRequests()
	},
}

const org = "Gosayram"
const repo = "kaniko"

func main() {
	// First try to get token from environment variable
	if envToken := os.Getenv("GITHUB_TOKEN"); envToken != "" {
		token = envToken
		fmt.Printf("Using GITHUB_TOKEN from environment variable\n")
	}

	rootCmd.Flags().StringVar(&token, "token", token,
		"Specify personal Github Token if you are hitting a rate limit anonymously. "+
			"https://github.com/settings/tokens (can also be set via GITHUB_TOKEN env var)")
	rootCmd.Flags().StringVar(&fromTag, "fromTag", "",
		"comparison of commits is based on this tag "+
			"(defaults to the latest tag in the repo)")
	rootCmd.Flags().StringVar(&toTag, "toTag", "master", "this is the commit that is compared with fromTag")

	// Add help text for the repository constants
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		fmt.Printf("Repository: https://github.com/%s/%s\n", org, repo)
		fmt.Printf("Organization: %s\n", org)
		fmt.Printf("Repository name: %s\n", repo)
		if token != "" {
			fmt.Printf("Using GitHub token: %s****\n", token[:4]) // Show only first 4 chars for security
		} else {
			fmt.Printf("No GitHub token provided (may hit rate limits)\n")
		}
		fmt.Println()
	}

	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}

func printPullRequests() {
	client := getClient()

	// Test API access first with a simple request
	fmt.Printf("Testing API access to https://github.com/%s/%s...\n", org, repo)

	// Try to get repository info to test access
	_, resp, err := client.Repositories.Get(context.Background(), org, repo)
	if err != nil {
		fmt.Printf("Error accessing repository: %v\n", err)
		fmt.Printf("Response status: %s\n", resp.Status)
		if resp.StatusCode == 403 {
			fmt.Printf("ERROR: Access forbidden. This might be due to:\n")
			fmt.Printf("1. Rate limiting - try with --token flag\n")
			fmt.Printf("2. Repository access restrictions\n")
			fmt.Printf("3. Invalid repository name\n")
		} else if resp.StatusCode == 404 {
			fmt.Printf("ERROR: Repository not found. Please check if '%s/%s' exists\n", org, repo)
		}
		return
	}
	fmt.Printf("Successfully accessed repository (status: %s)\n", resp.Status)

	var lastReleaseTime *github.Timestamp
	fmt.Printf("Fetching releases for %s/%s...\n", org, repo)
	releases, resp, err := client.Repositories.ListReleases(context.Background(), org, repo, &github.ListOptions{})
	if err != nil {
		fmt.Printf("Error fetching releases: %v\n", err)
		fmt.Printf("Response status: %s\n", resp.Status)
		// If no releases found, use a very old date to include all PRs
		oldDate := github.Timestamp{Time: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)}
		lastReleaseTime = &oldDate
		fmt.Printf("No releases found, will include all PRs since 2000-01-01\n")
	} else {
		fmt.Printf("Found %d releases\n", len(releases))
		if len(releases) > 0 {
			fmt.Printf("Latest release: %s (published: %s)\n", releases[0].GetName(), releases[0].GetPublishedAt().Format(time.RFC3339))
			lastReleaseTime = releases[0].PublishedAt
		} else {
			// If no releases found, use a very old date to include all PRs
			oldDate := github.Timestamp{Time: time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)}
			lastReleaseTime = &oldDate
			fmt.Printf("No releases found, will include all PRs since 2000-01-01\n")
		}
	}

	listSize := 1
	seen := map[int]bool{}
	prCount := 0

	fmt.Printf("Fetching pull requests since %s...\n", lastReleaseTime.Time.Format(time.RFC3339))
	for page := 0; listSize > 0; page++ {
		fmt.Printf("Fetching page %d of pull requests...\n", page+1)
		pullRequests, resp, err := client.PullRequests.List(context.Background(), org, repo, &github.PullRequestListOptions{
			State:     "closed",
			Sort:      "updated",
			Direction: "desc",
			ListOptions: github.ListOptions{
				PerPage: 100, //nolint:mnd // 100 is the standard page size for GitHub API
				Page:    page,
			},
		})

		if err != nil {
			fmt.Printf("Error fetching pull requests: %v\n", err)
			fmt.Printf("Response status: %s\n", resp.Status)
			break
		}

		fmt.Printf("Got %d pull requests on page %d\n", len(pullRequests), page+1)

		for idx := range pullRequests {
			pr := pullRequests[idx]
			if pr.MergedAt != nil {
				prCount++
				if _, ok := seen[*pr.Number]; !ok && pr.GetMergedAt().After(lastReleaseTime.Time) {
					fmt.Printf("* %s [#%d](https://github.com/%s/%s/pull/%d)\n",
						pr.GetTitle(), *pr.Number, org, repo, *pr.Number)
					seen[*pr.Number] = true
				}
			}
		}

		listSize = len(pullRequests)
	}

	fmt.Printf("Processed %d total pull requests, found %d merged PRs since last release\n", prCount, len(seen))
}

func getClient() *github.Client {
	if token == "" {
		return github.NewClient(nil)
	}
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	return github.NewClient(tc)
}
