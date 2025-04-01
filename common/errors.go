package common

import (
	"fmt"
	"strings"
)

var (
	ErrUnknownType = func(t, v string) error {
		if v == "" {
			return fmt.Errorf("unknown %s", t)
		}

		return fmt.Errorf("unknown %s: %s", t, v)
	}

	ErrNotFoundPerm = func(obj, action string) error {
		return fmt.Errorf("no permission found for object %s and action %s", obj, action)
	}

	ErrForbidden = func(p Permission) error {
		return forbiddenErr{perm: p}
	}
)

type forbiddenErr struct {
	perm Permission
}

// Returns an error message for permission. E.g. for permission "Can read an {object}" with ID,
// the message will be "You don't have the permission to read this {object}".
func (e forbiddenErr) Error() string {
	description := e.perm.GetDeniedDescription()
	if strings.Contains(description, "access") {
		return "You don't have " + description
	}
	return "You don't have the permission to " + description
}
