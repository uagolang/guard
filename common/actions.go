package common

import (
	"github.com/uagolang/guard/utils"
)

type Action string

func (a Action) String() string {
	return string(a)
}

func (a Action) List() any {
	return Actions
}

func (a Action) Strings() []string {
	return utils.Map(Actions, func(item Action, _ int) string {
		return item.String()
	})
}

func (a Action) Validate() error {
	if !utils.Contains(Actions, a) {
		return ErrUnknownType("action", a.String())
	}

	return nil
}

const (
	ActionList   Action = "list"
	ActionGet    Action = "get"
	ActionCreate Action = "create"
	ActionUpdate Action = "update"
	ActionDelete Action = "delete"

	ActionRoleAssign Action = "role-assign"
	ActionRoleRevoke Action = "role-revoke"
)

var Actions = []Action{
	ActionList, ActionGet, ActionCreate, ActionUpdate, ActionDelete, ActionRoleAssign, ActionRoleRevoke,
}
