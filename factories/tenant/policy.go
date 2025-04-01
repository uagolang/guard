package tenant

import (
	"github.com/uagolang/guard/common"
	"github.com/uagolang/guard/common/contracts"
)

// policy is a casbin entry of type p
type policy struct {
	sub    contracts.Subject
	scope  contracts.Scope
	perm   common.Perm
	effect string
}

func (p *policy) Sub() contracts.Subject {
	return p.sub
}

func (p *policy) Scope() contracts.Scope {
	return p.scope
}

func (p *policy) Perm() any {
	return p.perm
}

func (p *policy) Effect() string {
	return p.effect
}

func newPolicy(sub contracts.Subject, scope contracts.Scope, perm common.Perm, effect string) contracts.Policy {
	return &policy{
		sub:    sub,
		scope:  scope,
		perm:   perm,
		effect: effect,
	}
}

func newPolicyFromCasbin(permsList []common.Perm, s []string) (contracts.Policy, error) {
	sub, err := newSubjectFromCasbin(s[0])
	if err != nil {
		return nil, err
	}

	obj, err := NewObjFromCasbin(s[1])
	if err != nil {
		return nil, err
	}

	permAny, err := obj.GetPerm(permsList, s[2], "", "")
	if err != nil {
		return nil, err
	}

	perm, ok := permAny.(common.Perm)
	if !ok {
		return nil, common.ErrUnknownType("permission contract", "")
	}

	effect := s[3]

	return newPolicy(sub, obj.GetScope(), perm, effect), nil
}

type rolePolicy struct {
	scope  contracts.Scope
	perm   any
	effect string
}

func (p *rolePolicy) Scope() contracts.Scope {
	return p.scope
}

func (p *rolePolicy) Perm() any {
	return p.perm
}

func (p *rolePolicy) Effect() string {
	return p.effect
}

func (p *rolePolicy) ToCasbin(sub contracts.Subject) []string {
	obj := newObject().SetScope(p.scope).SetPerm(p.perm)
	perm := p.perm.(common.Perm)
	return []string{sub.ToCasbin(), obj.ToCasbin(), (&perm).GetAction(), p.effect}
}

func newRolePolicyFromCasbin(permsList []common.Perm, p []string) (contracts.RolePolicy, error) {
	pol, err := newPolicyFromCasbin(permsList, p)
	if err != nil {
		return nil, err
	}

	return &rolePolicy{
		scope:  pol.Scope(),
		perm:   pol.Perm(),
		effect: pol.Effect(),
	}, nil
}

// groupPolicy is a casbin entry of type g
type groupPolicy struct {
	// who inherits the policy
	subject contracts.Subject

	// what policy is inherited
	role contracts.Subject
}

func (gp *groupPolicy) ToCasbin() []string {
	return []string{gp.subject.ToCasbin(), gp.role.ToCasbin()}
}

func newGroupPolicy(subject, role contracts.Subject) contracts.GroupPolicy {
	return &groupPolicy{
		subject: subject,
		role:    role,
	}
}

func newGroupPolicyFromCasbin(s []string) (contracts.GroupPolicy, error) {
	sub, err := newSubjectFromCasbin(s[0])
	if err != nil {
		return nil, err
	}

	role, err := newSubjectFromCasbin(s[1])
	if err != nil {
		return nil, err
	}

	return newGroupPolicy(sub, role), nil
}
