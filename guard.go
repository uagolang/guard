package guard

import (
	"context"
	"errors"

	"github.com/casbin/casbin/v2"

	"github.com/uagolang/guard/common"
	"github.com/uagolang/guard/contracts"
	"github.com/uagolang/guard/utils"
)

type Guard struct {
	factory       contracts.Factory
	casbin        casbin.IEnforcer
	actions       []common.Action
	entityObjects []common.EntityObject
	perms         []contracts.Perm
	scopedObjects map[contracts.ScopeLevel][]common.EntityObject
}

func New(f contracts.Factory, e casbin.IEnforcer, opts ...Option) *Guard {
	g := &Guard{
		factory:       f,
		casbin:        e,
		perms:         common.Perms,
		actions:       common.Actions,
		entityObjects: common.EntityObjects,
		scopedObjects: defaultScopedObjects,
	}

	for _, opt := range opts {
		opt(g)
	}

	return g
}

// Casbin returns enforcer
func (g *Guard) Casbin() casbin.IEnforcer {
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
func (g *Guard) Perms() []contracts.Perm {
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
func (g *Guard) HasPerm(ctx context.Context, userID string, perm contracts.Perm, scopeData contracts.ScopeData) error {
	if err := g.validateScopes(perm, scopeData); err != nil {
		return err
	}

	return g.check(ctx, check{
		userID: userID,
		perm:   perm,
		scope:  g.factory.Scope(scopeData),
	})
}

func (g *Guard) ForceCheckPerm(ctx context.Context, userID string, perm contracts.Perm, scopeData contracts.ScopeData) error {
	if err := g.validateScopes(perm, scopeData); err != nil {
		return err
	}

	return g.check(ctx, check{
		userID:     userID,
		perm:       perm,
		scope:      g.factory.Scope(scopeData),
		forceCheck: true,
	})
}

func (g *Guard) HasPermInScope(ctx context.Context, userID string, perm contracts.Perm, scope contracts.Scope, forceCheckOpt ...bool) error {
	return g.check(ctx, check{
		userID:     userID,
		perm:       perm,
		scope:      scope,
		forceCheck: utils.SliceElem(forceCheckOpt, 0, false),
	})
}

type RoleRequest struct {
	Sub       contracts.Subject
	ScopeData contracts.ScopeData
	Policies  [][]string
}

func (g *Guard) CreateRole(i RoleRequest) error {
	sanitizedPolicies, err := g.sanitizeRolePolicies(sanitizeRolePolicies{
		scopeData:      i.ScopeData,
		casbinPolicies: i.Policies,
	})
	if err != nil {
		return err
	}

	policies := make([][]string, len(sanitizedPolicies))
	for idx, policy := range sanitizedPolicies {
		policies[idx] = policy.ToCasbin(i.Sub)
	}

	_, err = g.casbin.AddPoliciesEx(policies)
	return err
}

func (g *Guard) UpdateRole(ctx context.Context, userID string, i RoleRequest) error {
	if userID == "" {
		return errors.New("user id must not be empty")
	}

	sanitizedPolicies, err := g.sanitizeRolePolicies(sanitizeRolePolicies{
		scopeData:      i.ScopeData,
		casbinPolicies: i.Policies,
	})
	if err != nil {
		return err
	}

	filteredPolicies, err := g.casbin.GetFilteredPolicy(0, i.Sub.ToCasbin())
	if err != nil {
		return err
	}

	fPolicies, err := g.rolePoliciesFromCasbin(filteredPolicies)
	if err != nil {
		return err
	}

	removed, added := utils.Difference(fPolicies, sanitizedPolicies)
	if err := g.hasAllPolicies(ctx, userID, removed); err != nil {
		return err
	}
	if err := g.hasAllPolicies(ctx, userID, added); err != nil {
		return err
	}

	_, err = g.casbin.RemoveFilteredPolicy(0, i.Sub.ToCasbin())
	if err != nil {
		return err
	}

	policies := make([][]string, len(sanitizedPolicies))
	for idx, policy := range sanitizedPolicies {
		policies[idx] = policy.ToCasbin(i.Sub)
	}

	_, err = g.casbin.AddPoliciesEx(policies)
	return err
}

func (g *Guard) DeleteRole(ctx context.Context, userID string, sub contracts.Subject) error {
	if userID == "" {
		return errors.New("user id must not be empty")
	}

	if err := g.hasAllSubjectPerms(ctx, userID, sub); err != nil {
		return err
	}

	_, err := g.casbin.RemoveFilteredPolicy(0, sub.ToCasbin())
	if err != nil {
		return err
	}

	_, err = g.casbin.RemoveFilteredGroupingPolicy(1, sub.ToCasbin())
	if err != nil {
		return err
	}

	return nil
}

func (g *Guard) AssignRoles(sub contracts.Subject, roles ...contracts.Subject) error {
	casbinPolicies := utils.Map(roles, func(role contracts.Subject, _ int) []string {
		return g.factory.GroupPolicy(sub, role).ToCasbin()
	})

	_, err := g.casbin.AddGroupingPoliciesEx(casbinPolicies)
	return err
}

func (g *Guard) RevokeRoles(sub contracts.Subject, roles ...contracts.Subject) error {
	if len(roles) == 0 {
		_, err := g.casbin.RemoveFilteredGroupingPolicy(0, sub.ToCasbin())
		return err
	}

	for _, r := range roles {
		_, err := g.casbin.RemoveGroupingPolicy(g.factory.GroupPolicy(sub, r).ToCasbin())
		if err != nil {
			return err
		}
	}

	return nil
}

func (g *Guard) hasAllPolicies(ctx context.Context, userID string, policies []contracts.RolePolicy) error {
	for _, policy := range policies {
		err := g.check(ctx, check{
			userID:     userID,
			perm:       policy.Perm(),
			scope:      policy.Scope(),
			forceCheck: true,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (g *Guard) hasAllSubjectPerms(ctx context.Context, userID string, sub contracts.Subject) error {
	p, err := g.casbin.GetImplicitPermissionsForUser(sub.ToCasbin())
	if err != nil {
		return err
	}

	policies, err := g.factory.RolePoliciesFromCasbin(p)
	if err != nil {
		return err
	}

	return g.hasAllPolicies(ctx, userID, policies)
}

func (g *Guard) RemoveUserPerms(userID string) error {
	return g.RevokeRoles(g.factory.SubjectUser(userID))
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
		return p.Perm().GetObject() == object && p.Perm().GetObjectID() == objectID
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
	Admin  bool
	Object string
}

func (g *Guard) GetPermsByObject(i GetPermsByObjectRequest) ([]contracts.Perm, error) {
	return utils.Filter(g.perms, func(p contracts.Perm) bool {
		if i.Admin {
			return p.GetObject() == i.Object
		}

		return p.GetObject() == i.Object && !p.IsAdmin()
	}), nil
}

type sanitizeRolePolicies struct {
	scopeData      contracts.ScopeData
	casbinPolicies [][]string
}

func (g *Guard) sanitizeRolePolicies(i sanitizeRolePolicies) ([]contracts.RolePolicy, error) {
	res := make([]contracts.RolePolicy, len(i.casbinPolicies))

	rolePolicies, err := g.rolePoliciesFromCasbin(i.casbinPolicies)
	if err != nil {
		return nil, err
	}

	for idx, p := range rolePolicies {
		permission, err := common.GetPerm(g.perms, p.Perm().GetObject(), p.Perm().GetObjectID(), p.Perm().GetAction())
		if err != nil {
			return nil, err
		}

		res[idx] = p
		res[idx].SetPerm(permission).SetScope(g.factory.Scope(i.scopeData))
	}

	return res, nil
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

func (g *Guard) validateScopes(p contracts.Perm, data contracts.ScopeData) error {
	if data == nil || len(data) == 0 {
		return common.ErrForbidden(p)
	}

	return nil
}

type check struct {
	userID     string
	perm       contracts.Perm
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
	perm   contracts.Perm
	scope  contracts.Scope
}

func (g *Guard) hasPerm(i hasPerm) (bool, error) {
	sub := g.factory.SubjectUser(i.userID)
	obj := g.factory.Object(i.scope, i.perm)

	return g.casbin.Enforce(sub.ToCasbin(), obj.ToCasbin(), i.perm.GetAction())
}

var defaultScopedObjects = map[contracts.ScopeLevel][]common.EntityObject{
	contracts.ScopeLevelSystem: common.EntityObjects,
	contracts.ScopeLevelTenant: {
		common.EntityObjectOrg,
	},
}
