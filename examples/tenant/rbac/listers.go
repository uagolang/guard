package rbac

import (
	"github.com/uagolang/guard/common"
	"github.com/uagolang/guard/perms"
	"github.com/uagolang/guard/utils"
)

var (
	App perms.Lister = &app{Lister: perms.NewPermsLister(EntityObjectApp, "a role", "roles")}
)

var listers = []perms.Lister{App}

var AllPerms = utils.FlatMap(listers, func(lister perms.Lister) []common.Perm {
	return lister.Perms()
})

type app struct{ perms.Lister }

func (*app) Deploy() common.Perm {
	return common.Perm{
		Object: EntityObjectApp,
		Action: ActionDeploy,
		Name:   "Deploy",
		Desc:   "Deploy application",
	}
}
