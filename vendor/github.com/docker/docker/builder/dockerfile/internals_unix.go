//go:build !linux && !windows && !darwin

package dockerfile

import (
	"context"
	"strconv"
	"strings"

	"github.com/moby/sys/user"
	"github.com/pkg/errors"
)

// parseChownFlag parses the chown flag for Unix systems.
// This is a fallback implementation for systems that don't have
// Linux-specific user/group lookup capabilities.
func parseChownFlag(ctx context.Context, builder *Builder, state *dispatchState, chown, ctrRootPath string, identityMapping user.IdentityMapping) (identity, error) {
	var userStr, grpStr string
	parts := strings.Split(chown, ":")
	if len(parts) > 2 {
		return identity{}, errors.New("invalid chown string format: " + chown)
	}
	if len(parts) == 1 {
		// if no group specified, use the user spec as group as well
		userStr, grpStr = parts[0], parts[0]
	} else {
		userStr, grpStr = parts[0], parts[1]
	}

	// For Unix systems, we use a simplified approach with numeric IDs
	uid, err := parseUserID(userStr)
	if err != nil {
		return identity{}, errors.Wrap(err, "can't parse user ID: "+userStr)
	}

	gid, err := parseGroupID(grpStr)
	if err != nil {
		return identity{}, errors.Wrap(err, "can't parse group ID: "+grpStr)
	}

	// convert as necessary because of user namespaces
	uid, gid, err = identityMapping.ToHost(uid, gid)
	if err != nil {
		return identity{}, errors.Wrap(err, "unable to convert uid/gid to host mapping")
	}
	return identity{UID: uid, GID: gid}, nil
}

// parseUserID parses a user ID string, supporting both numeric IDs and common names
func parseUserID(userStr string) (int, error) {
	// if the string is actually a uid integer, parse to int and return
	uid, err := strconv.Atoi(userStr)
	if err == nil {
		return uid, nil
	}

	// For Unix systems, we support common user names with fallback to numeric parsing
	switch strings.ToLower(userStr) {
	case "root":
		return 0, nil
	case "daemon":
		return 1, nil
	case "nobody":
		return 65534, nil
	default:
		// Try to parse as numeric ID
		return strconv.Atoi(userStr)
	}
}

// parseGroupID parses a group ID string, supporting both numeric IDs and common names
func parseGroupID(groupStr string) (int, error) {
	// if the string is actually a gid integer, parse to int and return
	gid, err := strconv.Atoi(groupStr)
	if err == nil {
		return gid, nil
	}

	// For Unix systems, we support common group names with fallback to numeric parsing
	switch strings.ToLower(groupStr) {
	case "root":
		return 0, nil
	case "daemon":
		return 1, nil
	case "nobody":
		return 65534, nil
	default:
		// Try to parse as numeric ID
		return strconv.Atoi(groupStr)
	}
}
