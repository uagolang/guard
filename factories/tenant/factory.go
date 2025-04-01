package tenant

import (
	"github.com/uagolang/guard/common"
	"github.com/uagolang/guard/common/contracts"
)

type factory struct {
	perms []common.Perm
}

func NewFactory(permsList ...common.Perm) contracts.Factory {
	return &factory{perms: permsList}
}

func (f *factory) Scope(data ...string) contracts.Scope {
	if len(data) == 0 {
		return newScope()
	}

	return newScope(WithData(
		map[string]string{ScopeDataTenantIDName: data[0]},
	))
}

func (f *factory) SubjectUser(id string) contracts.Subject {
	return newSubjectUser(id)
}

func (f *factory) SubjectRole(tenantID, id string) contracts.Subject {
	return newSubjectRole(tenantID, id)
}

func (f *factory) SubjectGroup(tenantID, id string) contracts.Subject {
	return newSubjectGroup(tenantID, id)
}

func (f *factory) Object(s contracts.Scope, p any) contracts.Object {
	return newObject().SetScope(s).SetPerm(p)
}

func (f *factory) GroupPolicy(sub, role contracts.Subject) contracts.GroupPolicy {
	return newGroupPolicy(sub, role)
}

func (f *factory) PolicyFromCasbin(p []string) (contracts.Policy, error) {
	return newPolicyFromCasbin(f.perms, p)
}

func (f *factory) RolePolicyFromCasbin(p []string) (contracts.RolePolicy, error) {
	return newRolePolicyFromCasbin(f.perms, p)
}

func (f *factory) GroupPolicyFromCasbin(s []string) (contracts.GroupPolicy, error) {
	return newGroupPolicyFromCasbin(s)
}
