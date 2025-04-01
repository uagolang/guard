package rbac

import (
	"github.com/uagolang/guard/common"
)

const (
	ActionDeploy = common.Action("app-deploy")
)

var Actions = []common.Action{ActionDeploy}
