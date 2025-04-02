package common

import (
	"fmt"
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
)
