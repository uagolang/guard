package common

import (
	"strings"

	"github.com/uagolang/guard/contracts"
)

var ErrForbidden = func(p contracts.Perm) error {
	return forbiddenErr{perm: p}
}

type forbiddenErr struct {
	perm contracts.Perm
}

// Returns an error message for permission. E.g. for permission "Can read an {object}" with ID,
// the message will be "you don't have the permission to read this {object}".
func (e forbiddenErr) Error() string {
	description := e.perm.GetDeniedDescription()
	if strings.Contains(description, "access") {
		return "you don't have " + description
	}
	return "you don't have the permission to " + description
}
