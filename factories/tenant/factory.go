package tenant

import (
	"github.com/uagolang/guard/contracts"
	"github.com/uagolang/guard/examples/tenant/rbac"
)

type factory struct {
	perms []contracts.Perm
}

func NewFactory(permsList ...contracts.Perm) contracts.Factory {
	return &factory{perms: append(rbac.AllPerms, permsList...)}
}

func (f *factory) Scope(data contracts.ScopeData) contracts.Scope {
	if len(data) == 0 {
		return newScope()
	}

	return newScope(WithData(data))
}

func (f *factory) SubjectUser(id string) contracts.Subject {
	return NewSubjectUser(id)
}

func (f *factory) SubjectRole(tenantID, id string) contracts.Subject {
	return NewSubjectRole(tenantID, id)
}

func (f *factory) SubjectGroup(tenantID, id string) contracts.Subject {
	return NewSubjectGroup(tenantID, id)
}

func (f *factory) Object(s contracts.Scope, p contracts.Perm) contracts.Object {
	return NewObject().SetScope(s).SetPerm(p)
}

func (f *factory) GroupPolicy(sub, role contracts.Subject) contracts.GroupPolicy {
	return NewGroupPolicy(sub, role)
}

func (f *factory) PolicyFromCasbin(p []string) (contracts.Policy, error) {
	return newPolicyFromCasbin(f.perms, p)
}

func (f *factory) RolePolicyFromCasbin(p []string) (contracts.RolePolicy, error) {
	return newRolePolicyFromCasbin(f.perms, p)
}

func (f *factory) RolePoliciesFromCasbin(p [][]string) ([]contracts.RolePolicy, error) {
	res := make([]contracts.RolePolicy, len(p))
	for idx, pol := range p {
		rPolicy, err := newRolePolicyFromCasbin(f.perms, pol)
		if err != nil {
			return nil, err
		}

		res[idx] = rPolicy
	}

	return res, nil
}

func (f *factory) GroupPolicyFromCasbin(s []string) (contracts.GroupPolicy, error) {
	return newGroupPolicyFromCasbin(s)
}
