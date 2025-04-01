package guard

import (
	"context"

	"github.com/casbin/casbin/v2"

	"github.com/uagolang/guard/common"
	"github.com/uagolang/guard/common/contracts"
	"github.com/uagolang/guard/utils"
)

type Guard struct {
	factory       contracts.Factory
	casbin        *casbin.Enforcer
	actions       []common.Action
	entityObjects []common.EntityObject
	perms         []common.Perm
	scopedObjects map[contracts.ScopeLevel][]common.EntityObject
}

func New(opts ...Option) *Guard {
	g := new(Guard)
	for _, opt := range opts {
		opt(g)
	}

	return g
}

// Casbin returns enforcer
func (g *Guard) Casbin() *casbin.Enforcer {
	return g.casbin
}

// Actions returns slice of guard actions
func (g *Guard) Actions() []common.Action {
	return g.actions
}

// EntityObjects returns slice of entity objects
func (g *Guard) EntityObjects() []common.EntityObject {
	return g.entityObjects
}

// Perms returns slice of perms
func (g *Guard) Perms() []common.Perm {
	return g.perms
}

// ScopedObjects returns map with key contracts.ScopeLevel and value - slice of entity objects
func (g *Guard) ScopedObjects() map[contracts.ScopeLevel][]common.EntityObject {
	return g.scopedObjects
}

// GetScopeObjects returns slice of objects filtered by contracts.ScopeLevel
func (g *Guard) GetScopeObjects(level contracts.ScopeLevel) []common.EntityObject {
	return g.scopedObjects[level]
}

// HasPerm checks user access slice of objects filtered by contracts.ScopeLevel
func (g *Guard) HasPerm(ctx context.Context, userID string, perm *common.Perm, scopes ...string) error {
	if err := g.validateScopes(perm, scopes...); err != nil {
		return err
	}

	return g.check(ctx, check{
		userID: userID,
		perm:   perm,
		scope:  g.factory.Scope(scopes[0]),
	})
}

func (g *Guard) ForceCheckPerm(ctx context.Context, userID string, perm *common.Perm, scopes ...string) error {
	if err := g.validateScopes(perm, scopes...); err != nil {
		return err
	}

	return g.check(ctx, check{
		userID:     userID,
		perm:       perm,
		scope:      g.factory.Scope(scopes[0]),
		forceCheck: true,
	})
}

func (g *Guard) HasPermInScope(ctx context.Context, userID string, perm *common.Perm, scope contracts.Scope, forceCheckOpt ...bool) error {
	return g.check(ctx, check{
		userID:     userID,
		perm:       perm,
		scope:      scope,
		forceCheck: utils.SliceElem(forceCheckOpt, 0, false),
	})
}

func (g *Guard) AddRoleToSubject(role, sub contracts.Subject) error {
	_, err := g.casbin.AddGroupingPolicy(g.factory.GroupPolicy(sub, role).ToCasbin())
	return err
}

func (g *Guard) AddRolesToSubject(roles []contracts.Subject, sub contracts.Subject) error {
	casbinPolicies := utils.Map(roles, func(role contracts.Subject, _ int) []string {
		return g.factory.GroupPolicy(sub, role).ToCasbin()
	})
	_, err := g.casbin.AddGroupingPoliciesEx(casbinPolicies)
	return err
}

func (g *Guard) RemoveRoleFromSubject(role, sub contracts.Subject) error {
	_, err := g.casbin.RemoveGroupingPolicy(g.factory.GroupPolicy(sub, role).ToCasbin())
	return err
}

func (g *Guard) RemoveAllRolesFromSubject(sub contracts.Subject) error {
	_, err := g.casbin.RemoveFilteredGroupingPolicy(0, sub.ToCasbin())
	return err
}

func (g *Guard) HasAllPolicies(ctx context.Context, userID string, policies []contracts.RolePolicy) error {
	for _, policy := range policies {
		err := g.check(ctx, check{
			userID:     userID,
			perm:       policy.Perm().(*common.Perm),
			scope:      policy.Scope(),
			forceCheck: true,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (g *Guard) HasAllSubjectPerms(ctx context.Context, userID string, sub contracts.Subject) error {
	p, err := g.casbin.GetImplicitPermissionsForUser(sub.ToCasbin())
	if err != nil {
		return err
	}

	policies, err := g.rolePoliciesFromCasbin(p)
	if err != nil {
		return err
	}

	return g.HasAllPolicies(ctx, userID, policies)
}

func (g *Guard) RemoveUserPerms(userID string) error {
	return g.RemoveAllRolesFromSubject(g.factory.SubjectUser(userID))
}

func (g *Guard) GetFilteredPolicies(filter func(pol contracts.Policy) bool) ([][]string, error) {
	policy, err := g.casbin.GetPolicy()
	if err != nil {
		return nil, err
	}

	return utils.Filter(policy, func(casbinPolicy []string) bool {
		p, err := g.factory.PolicyFromCasbin(casbinPolicy)
		return err == nil && filter(p)
	}), nil
}

func (g *Guard) RemoveObjectPerms(object, objectID string) error {
	policies, err := g.GetFilteredPolicies(func(p contracts.Policy) bool {
		perm := p.Perm().(common.Perm)
		return perm.GetObject() == object && perm.GetObjectID() == objectID
	})
	if err != nil {
		return err
	}

	_, err = g.casbin.RemovePolicies(policies)
	return err
}

func (g *Guard) RemoveScopePerms(scope contracts.Scope) error {
	policies, err := g.GetFilteredPolicies(func(p contracts.Policy) bool {
		return scope.Contains(p.Scope())
	})
	if err != nil {
		return err
	}

	_, err = g.casbin.RemovePolicies(policies)
	return err
}

type GetPermsByObjectRequest struct {
	Object string
}

func (g *Guard) GetPermsByObject(req GetPermsByObjectRequest) ([]common.Perm, error) {
	return utils.Filter(g.perms, func(p common.Perm) bool {
		if p.Admin {
			return p.Object.String() == req.Object
		}

		return p.Object.String() == req.Object && !p.Admin
	}), nil
}

func (g *Guard) rolePoliciesFromCasbin(p [][]string) ([]contracts.RolePolicy, error) {
	var err error
	policies := utils.Map(p, func(item []string, _ int) contracts.RolePolicy {
		pol, e := g.factory.RolePolicyFromCasbin(item)
		if e != nil {
			err = e
			return nil
		}

		return pol
	})

	res := make([]contracts.RolePolicy, 0)
	// remove nil values
	for _, policy := range policies {
		if policy != nil {
			res = append(res, policy)
		}
	}

	return res, err
}

func (g *Guard) validateScopes(p *common.Perm, scopes ...string) error {
	if len(scopes) == 0 {
		return common.ErrForbidden(p)
	}

	return nil
}

type check struct {
	userID     string
	perm       *common.Perm
	scope      contracts.Scope
	forceCheck bool
}

func (g *Guard) check(ctx context.Context, i check) error {
	if !i.forceCheck && isCheckDisabled(ctx) {
		return nil
	}

	ok, err := g.hasPerm(hasPerm{
		userID: i.userID,
		perm:   i.perm,
		scope:  i.scope,
	})
	if err != nil {
		return err
	}

	if !ok {
		return common.ErrForbidden(i.perm)
	}

	if !i.forceCheck {
		DisableCheckPerms(ctx)
	}

	return nil
}

type hasPerm struct {
	userID string
	perm   *common.Perm
	scope  contracts.Scope
}

func (g *Guard) hasPerm(i hasPerm) (bool, error) {
	sub := g.factory.SubjectUser(i.userID)
	obj := g.factory.Object(i.scope, i.perm)

	return g.casbin.Enforce(sub.ToCasbin(), obj.ToCasbin(), i.perm.GetAction())
}
