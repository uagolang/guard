package tenant

import (
	"github.com/uagolang/guard/contracts"
)

// Policy is a casbin entry of type p
type Policy struct {
	sub    contracts.Subject
	scope  contracts.Scope
	perm   contracts.Perm
	effect string
}

func (p *Policy) Sub() contracts.Subject {
	return p.sub
}

func (p *Policy) Scope() contracts.Scope {
	return p.scope
}

func (p *Policy) Perm() contracts.Perm {
	return p.perm
}

func (p *Policy) Effect() string {
	return p.effect
}

func NewPolicy(sub contracts.Subject, scope contracts.Scope, perm contracts.Perm, effect string) contracts.Policy {
	return &Policy{
		sub:    sub,
		scope:  scope,
		perm:   perm,
		effect: effect,
	}
}

func newPolicyFromCasbin(permsList []contracts.Perm, s []string) (contracts.Policy, error) {
	sub, err := newSubjectFromCasbin(s[0])
	if err != nil {
		return nil, err
	}

	obj, err := NewObjFromCasbin(s[1])
	if err != nil {
		return nil, err
	}

	perm, err := obj.GetPerm(permsList, s[2])
	if err != nil {
		return nil, err
	}

	effect := s[3]

	return NewPolicy(sub, obj.GetScope(), perm, effect), nil
}

type RolePolicy struct {
	scope  contracts.Scope
	perm   contracts.Perm
	effect string
}

func (p *RolePolicy) SetScope(s contracts.Scope) contracts.RolePolicy {
	p.scope = s
	return p
}

func (p *RolePolicy) Scope() contracts.Scope {
	return p.scope
}

func (p *RolePolicy) SetPerm(perm contracts.Perm) contracts.RolePolicy {
	p.perm = perm
	return p
}

func (p *RolePolicy) Perm() contracts.Perm {
	return p.perm
}

func (p *RolePolicy) Effect() string {
	return p.effect
}

func (p *RolePolicy) ToCasbin(sub contracts.Subject) []string {
	obj := NewObject().SetScope(p.scope).SetPerm(p.perm)
	return []string{sub.ToCasbin(), obj.ToCasbin(), p.perm.GetAction(), p.effect}
}

func newRolePolicyFromCasbin(permsList []contracts.Perm, p []string) (contracts.RolePolicy, error) {
	pol, err := newPolicyFromCasbin(permsList, p)
	if err != nil {
		return nil, err
	}

	return &RolePolicy{
		scope:  pol.Scope(),
		perm:   pol.Perm(),
		effect: pol.Effect(),
	}, nil
}

// GroupPolicy is a casbin entry of type g
type GroupPolicy struct {
	// who inherits the Policy
	subject contracts.Subject

	// what Policy is inherited
	role contracts.Subject
}

func (gp *GroupPolicy) ToCasbin() []string {
	return []string{gp.subject.ToCasbin(), gp.role.ToCasbin()}
}

func NewGroupPolicy(subject, role contracts.Subject) contracts.GroupPolicy {
	return &GroupPolicy{
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

	return NewGroupPolicy(sub, role), nil
}
