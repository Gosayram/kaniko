#!/bin/bash

# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
EXAMPLES_DIR=${DIR}/../examples

# Read version from .release-version file
if [ -f .release-version ]; then
    MAKEFILE_VERSION=$(cat .release-version)
    VERSION="v$MAKEFILE_VERSION"
    echo "Using version from .release-version: $VERSION"
else
    # Prompt the user for the version
    echo -n "Enter the version for this release - ex: v1.14.0: "
    read VERSION
    
    # Remove 'v' prefix from version
    MAKEFILE_VERSION=$(echo $VERSION | sed 's/^[v]//')
fi

# Extract major, minor, and build version numbers
VERSION_MAJOR=$(echo $MAKEFILE_VERSION | cut -d. -f1)
VERSION_MINOR=$(echo $MAKEFILE_VERSION | cut -d. -f2)
VERSION_BUILD=$(echo $MAKEFILE_VERSION | cut -d. -f3)

echo "Processing (takes some time)..."

# Get the current date
DATE=$(date +'%Y-%m-%d')

# you can pass your github token with --token here if you run out of requests
# Capture only the actual pull request data, redirect debug output to stderr
PULL_REQS=$(go run ${DIR}/release_notes/listpullreqs.go 2>/dev/null | tr '\n' '|')
# Get contributors - handle case when no tags exist
# Try to get from Signed-off-by first (more reliable), fallback to author name
CONTRIBUTORS=""
if git describe --tags --abbrev=0 >/dev/null 2>&1; then
    LATEST_TAG=$(git describe --tags --abbrev=0)
    echo "Getting contributors between $LATEST_TAG and HEAD..."
    # First try to get from Signed-off-by lines (more reliable)
    CONTRIBUTORS=$(git log --no-merges --format="%B" --reverse "$LATEST_TAG"..HEAD 2>/dev/null | \
        grep -i "^Signed-off-by:" | \
        sed 's/^Signed-off-by:[[:space:]]*//' | \
        sed 's/[[:space:]]*<.*>.*$//' | \
        grep -v '^[[:space:]]*$' | \
        sort -u | \
        awk 'NF && length($0) > 0 {printf "- %s\n", $0}' | \
        tr '\n' '|')
    
    # If no Signed-off-by found, try author names (but filter out --show-origin)
    if [ -z "$CONTRIBUTORS" ] || [ "$CONTRIBUTORS" = "|" ]; then
        echo "No Signed-off-by found, trying author names..."
        CONTRIBUTORS=$(git log --no-merges --format="%aN" --reverse "$LATEST_TAG"..HEAD 2>/dev/null | \
            grep -v '^[[:space:]]*$' | \
            grep -v '^--show-origin$' | \
            sort -u | \
            awk 'NF && length($0) > 0 {printf "- %s\n", $0}' | \
            tr '\n' '|')
    fi
else
    echo "No tags found, getting all contributors from beginning..."
    # First try Signed-off-by
    CONTRIBUTORS=$(git log --no-merges --format="%B" --reverse 2>/dev/null | \
        grep -i "^Signed-off-by:" | \
        sed 's/^Signed-off-by:[[:space:]]*//' | \
        sed 's/[[:space:]]*<.*>.*$//' | \
        grep -v '^[[:space:]]*$' | \
        sort -u | \
        awk 'NF && length($0) > 0 {printf "- %s\n", $0}' | \
        tr '\n' '|')
    
    # Fallback to author names
    if [ -z "$CONTRIBUTORS" ] || [ "$CONTRIBUTORS" = "|" ]; then
        CONTRIBUTORS=$(git log --no-merges --format="%aN" --reverse 2>/dev/null | \
            grep -v '^[[:space:]]*$' | \
            grep -v '^--show-origin$' | \
            sort -u | \
            awk 'NF && length($0) > 0 {printf "- %s\n", $0}' | \
            tr '\n' '|')
    fi
fi

# Debug: show how many contributors were found
CONTRIB_COUNT=$(echo "$CONTRIBUTORS" | tr '|' '\n' | grep -c '^-' || echo "0")
echo "Found $CONTRIB_COUNT contributors"

# If no contributors found, set empty string (will leave header but no list)
if [ -z "$CONTRIBUTORS" ] || [ "$CONTRIBUTORS" = "|" ]; then
    echo "Warning: No contributors found between tags. The contributors section will show only the header."
    CONTRIBUTORS=""
fi

# Substitute placeholders with actual data in the template
TEMP_CHANGELOG=$(mktemp)
TEMP_CHANGELOG_FIXED=$(mktemp)
sed -e "s#{{PULL_REQUESTS}}#${PULL_REQS}#g" \
    -e "s#{{CONTRIBUTORS}}#${CONTRIBUTORS}#g" \
    -e "s#{{VERSION}}#${VERSION}#g" \
    -e "s#{{DATE}}#${DATE}#g" \
    ${DIR}/release_notes/changelog_template.txt > $TEMP_CHANGELOG

# Replace '|' with '\n' in temporary changelog
sed 's/|/\n/g' $TEMP_CHANGELOG > $TEMP_CHANGELOG_FIXED

# Prepend to CHANGELOG.md
cat $TEMP_CHANGELOG_FIXED CHANGELOG.md > TEMP && mv TEMP CHANGELOG.md

echo "Prepended the following release information to CHANGELOG.md"
echo ""
cat  $TEMP_CHANGELOG_FIXED

# Optionally, clean up the fixed temporary changlog file
rm $TEMP_CHANGELOG_FIXED

# Cleanup
rm $TEMP_CHANGELOG

echo "Updated .release-version for the new version: $VERSION"
# Update .release-version file
echo "$MAKEFILE_VERSION" > .release-version

# Also update Makefile for backward compatibility during transition
echo "Updating Makefile for backward compatibility..."
sed -i.bak \
    -e "s|VERSION_MAJOR ?=.*|VERSION_MAJOR ?= $VERSION_MAJOR|" \
    -e "s|VERSION_MINOR ?=.*|VERSION_MINOR ?= $VERSION_MINOR|" \
    -e "s|VERSION_BUILD ?=.*|VERSION_BUILD ?= $VERSION_BUILD|" \
    ./Makefile

# Cleanup
rm ./Makefile.bak
