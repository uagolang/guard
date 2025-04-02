package rbac

import (
	"github.com/uagolang/guard/common"
	"github.com/uagolang/guard/contracts"
	"github.com/uagolang/guard/utils"
)

var (
	App common.Lister = &app{Lister: common.NewPermsLister(EntityObjectApp, "a role", "roles")}
)

var listers = []common.Lister{App}

var AllPerms = utils.FlatMap(listers, func(lister common.Lister) []contracts.Perm {
	return lister.Perms()
})

type app struct{ common.Lister }

func (*app) Deploy() contracts.Perm {
	return &common.Permission{
		Object: EntityObjectApp,
		Action: ActionDeploy,
		Name:   "Deploy",
		Desc:   "Deploy application",
	}
}
