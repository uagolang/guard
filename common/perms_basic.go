package common

import (
	"github.com/uagolang/guard/contracts"
	"github.com/uagolang/guard/utils"
)

var (
	All            = NewPermsLister(EntityObjectAll, "any resource", "all resources")
	User           = NewPermsLister(EntityObjectUser, "a user", "users")
	Org            = NewPermsLister(EntityObjectOrg, "an organization", "organizations")
	OrgUser        = NewPermsLister(EntityObjectOrgUser, "an organization user", "organization users")
	Role    Lister = &role{permsLister: NewPermsLister(EntityObjectRole, "a role", "roles").(*permsLister)}
)

type role struct{ *permsLister }

func (*role) Assign() contracts.Perm {
	return &Permission{
		Object: EntityObjectRole,
		Action: ActionRoleAssign,
		Name:   "Assign",
		Desc:   "Assign roles to users and groups, add users to groups",
	}
}

func (*role) Revoke() contracts.Perm {
	return &Permission{
		Object: EntityObjectRole,
		Action: ActionRoleRevoke,
		Name:   "Revoke",
		Desc:   "Revoke roles from users and groups, remove users from groups",
	}
}

func (r *role) Perms() []contracts.Perm {
	return append(
		r.permsLister.Perms(),
		r.Assign(),
		r.Revoke(),
	)
}

var Perms = utils.FlatMap(listers, func(lister Lister) []contracts.Perm {
	return lister.Perms()
})
