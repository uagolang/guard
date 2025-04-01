package perms

import (
	"github.com/uagolang/guard/common"
	"github.com/uagolang/guard/utils"
)

var (
	All            = NewPermsLister(common.EntityObjectAll, "any resource", "all resources")
	User           = NewPermsLister(common.EntityObjectUser, "a user", "users")
	Org            = NewPermsLister(common.EntityObjectOrg, "an organization", "organizations")
	OrgUser        = NewPermsLister(common.EntityObjectOrgUser, "an organization user", "organization users")
	Role    Lister = &role{permsLister: NewPermsLister(common.EntityObjectRole, "a role", "roles").(*permsLister)}
)

type role struct{ *permsLister }

func (*role) Assign() common.Perm {
	return common.Perm{
		Object: common.EntityObjectRole,
		Action: common.ActionRoleAssign,
		Name:   "Assign",
		Desc:   "Assign roles to users and groups, add users to groups",
	}
}

func (*role) Revoke() common.Perm {
	return common.Perm{
		Object: common.EntityObjectRole,
		Action: common.ActionRoleRevoke,
		Name:   "Revoke",
		Desc:   "Revoke roles from users and groups, remove users from groups",
	}
}

func (r *role) Perms() []common.Perm {
	return append(
		r.permsLister.Perms(),
		r.Assign(),
		r.Revoke(),
	)
}

var AllPerms = utils.FlatMap(listers, func(lister Lister) []common.Perm {
	return lister.Perms()
})
