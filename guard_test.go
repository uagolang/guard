package guard

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/uagolang/guard/common"
	"github.com/uagolang/guard/contracts"
	factorytenant "github.com/uagolang/guard/factories/tenant"
	"github.com/uagolang/guard/mocks"
)

func TestGuard(t *testing.T) {
	factory := factorytenant.NewFactory()

	tenantID, roleID, userID := "org", "admin", "user1"

	scopeData := contracts.ScopeData{factorytenant.ScopeDataTenantIDName: tenantID}
	scope := &factorytenant.Scope{SystemName: "System", TenantName: "Tenant", Data: scopeData}

	userSub, roleSub := factorytenant.NewSubjectUser(userID), factorytenant.NewSubjectRole(tenantID, roleID)

	permOrgAll := common.Org.All()
	permOrgUpdate := common.Org.Update()

	mockErr := errors.New("mock error")
	ctrl := gomock.NewController(t)
	objUpdate := factory.Object(scope, permOrgUpdate)
	objAll := factory.Object(scope, permOrgAll)
	forbiddenErr := common.ErrForbidden(permOrgUpdate)

	policy := factorytenant.NewPolicy(userSub, scope, permOrgUpdate, "allow")
	//policy2 := factorytenant.NewPolicy(userSub, scope, permOrgAll, "allow")
	policySlice := [][]string{{policy.Sub().ToCasbin(), objUpdate.ToCasbin(), common.ActionUpdate.String(), policy.Effect()}}

	rolePolicy := (new(factorytenant.RolePolicy)).SetScope(scope).SetPerm(permOrgUpdate)
	rolePolicy2 := (new(factorytenant.RolePolicy)).SetScope(scope).SetPerm(permOrgAll)
	rolePolicyUnexpected := (new(factorytenant.RolePolicy)).SetScope(scope).SetPerm(&common.Permission{
		Name:   "unexpected perm",
		Object: "object",
		Action: "action",
	})

	groupPolicy := factorytenant.NewGroupPolicy(userSub, roleSub)

	mockCasbin := mocks.NewMockCasbin(ctrl)
	mockFactory := mocks.NewMockFactory(ctrl)
	g := New(mockFactory, mockCasbin)

	casbinPoliciesToAdd := [][]string{rolePolicy.ToCasbin(roleSub), rolePolicy2.ToCasbin(roleSub)}
	rolePoliciesToAdd := []contracts.RolePolicy{rolePolicy, rolePolicy2}
	lenRolePoliciesToAdd := len(rolePoliciesToAdd)

	t.Run("factory: tenant", func(t *testing.T) {

		t.Run("getters", func(t *testing.T) {
			assert.NotNil(t, g.Casbin())
			assert.NotNil(t, g.Actions())
			assert.NotNil(t, g.EntityObjects())
			assert.NotNil(t, g.Perms())
			assert.NotNil(t, g.ScopedObjects())
			assert.NotNil(t, g.GetScopeObjects(contracts.ScopeLevelTenant))
		})

		t.Run("validate scope", func(t *testing.T) {
			t.Run("error: nil scope data", func(t *testing.T) {
				perm := permOrgUpdate
				err := g.validateScopes(perm, nil)
				assert.Error(t, err)
				assert.Equal(t, forbiddenErr, err, "scope data should not be nil")
			})

			t.Run("error: empty scope data", func(t *testing.T) {
				perm := permOrgUpdate
				err := g.validateScopes(perm, contracts.ScopeData{})
				assert.Error(t, err)
				assert.Equal(t, forbiddenErr, err, "scope data should not be empty")
			})

			t.Run("success", func(t *testing.T) {
				perm := permOrgUpdate
				err := g.validateScopes(perm, scopeData)
				assert.NoError(t, err, "this case should work as expected, with no errors")
			})
		})

		t.Run("hasPerm", func(t *testing.T) {
			t.Run("denied", func(t *testing.T) {
				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub)
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(factorytenant.NewObject(tenantID))
				mockCasbin.EXPECT().Enforce(gomock.Any()).Return(false, nil)
				has, err := g.hasPerm(hasPerm{userID: userID, perm: permOrgUpdate, scope: scope})
				assert.False(t, has, "user should not have access")
				assert.NoError(t, err, "expected no error")
			})

			t.Run("allowed", func(t *testing.T) {
				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub)
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(factorytenant.NewObject(tenantID))
				mockCasbin.EXPECT().Enforce(gomock.Any()).Return(true, nil)
				has, err := g.hasPerm(hasPerm{userID: userID, perm: permOrgUpdate, scope: scope})
				assert.True(t, has, "user should not have access")
				assert.NoError(t, err, "expected no error")
			})

			t.Run("casbin error", func(t *testing.T) {
				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub)
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(factorytenant.NewObject(tenantID))
				mockCasbin.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, mockErr)

				has, err := g.hasPerm(hasPerm{userID: userID, perm: permOrgUpdate, scope: scope})
				assert.False(t, has)
				assert.Error(t, err)
			})
		})

		t.Run("check", func(t *testing.T) {
			t.Run("disabled via context", func(t *testing.T) {
				ctx := Context(context.Background())
				DisableCheckPerms(ctx)
				err := g.check(ctx, check{userID: userID, perm: permOrgUpdate, scope: scope})
				assert.NoError(t, err, "check was disabled, so no error here should appears")
			})

			t.Run("disabled via context, but force check is true", func(t *testing.T) {
				ctx := Context(context.Background())
				DisableCheckPerms(ctx)

				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub)
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(objUpdate)
				mockCasbin.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)

				err := g.check(ctx, check{userID: userID, perm: permOrgUpdate, scope: scope, forceCheck: true})
				assert.NoError(t, err)
			})

			t.Run("error: hasPerm internal", func(t *testing.T) {
				perm := permOrgUpdate

				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub)
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(objUpdate)
				mockCasbin.EXPECT().Enforce(gomock.Any()).Return(false, mockErr)

				err := g.check(context.Background(), check{userID: userID, perm: perm, scope: scope})
				assert.Error(t, err, "should not be forbidden here")
			})

			t.Run("error: forbidden", func(t *testing.T) {
				perm := permOrgUpdate

				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub)
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(objUpdate)
				mockCasbin.EXPECT().Enforce(gomock.Any()).Return(false, nil)

				err := g.check(context.Background(), check{userID: userID, perm: perm, scope: scope})
				assert.Equal(t, forbiddenErr, err, "should be forbidden here")
			})

			t.Run("success: allowed", func(t *testing.T) {
				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub)
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(factorytenant.NewObject(tenantID))
				mockCasbin.EXPECT().Enforce(gomock.Any()).Return(true, nil)
				ctx := Context(context.Background())

				err := g.check(ctx, check{userID: userID, perm: permOrgUpdate, scope: scope})
				assert.NoError(t, err, "should be no error")
				assert.True(t, isCheckDisabled(ctx))
			})

			t.Run("success: allowed with force check", func(t *testing.T) {
				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub)
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(objUpdate)
				mockCasbin.EXPECT().Enforce(gomock.Any()).Return(true, nil)
				ctx := Context(context.Background())
				require.False(t, isCheckDisabled(ctx))

				err := g.check(ctx, check{userID: userID, perm: permOrgUpdate, scope: scope, forceCheck: true})
				assert.NoError(t, err)
				assert.False(t, isCheckDisabled(ctx))
			})
		})

		t.Run("HasPerm", func(t *testing.T) {
			t.Run("error: validation", func(t *testing.T) {
				err := g.HasPerm(context.Background(), userID, permOrgUpdate, contracts.ScopeData{})
				assert.Error(t, err)
				assert.Equal(t, forbiddenErr, err)
			})

			t.Run("error: check returns error", func(t *testing.T) {
				mockFactory.EXPECT().Scope(gomock.Any()).Return(scope)
				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub)
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(objUpdate)
				mockCasbin.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, mockErr)

				err := g.HasPerm(context.Background(), userID, permOrgUpdate, scopeData)
				assert.Error(t, err)
				assert.Equal(t, mockErr, err)
			})

			t.Run("success: allowed", func(t *testing.T) {
				mockFactory.EXPECT().Scope(gomock.Any()).Return(scope)
				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub)
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(objUpdate)
				mockCasbin.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)

				err := g.HasPerm(context.Background(), userID, permOrgUpdate, scopeData)
				assert.NoError(t, err)
			})

		})

		t.Run("ForceCheckPerm", func(t *testing.T) {
			ctx := Context(context.Background())
			DisableCheckPerms(ctx)

			t.Run("error: validation", func(t *testing.T) {
				err := g.ForceCheckPerm(ctx, userID, permOrgUpdate, contracts.ScopeData{})
				assert.Error(t, err)
				assert.Equal(t, forbiddenErr, err)
			})

			t.Run("error: forbidden (even though context disabled)", func(t *testing.T) {
				mockFactory.EXPECT().Scope(gomock.Any()).Return(scope)
				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub)
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(objUpdate)
				mockCasbin.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil)

				err := g.ForceCheckPerm(ctx, userID, permOrgUpdate, scopeData)
				assert.Error(t, err)
				assert.Equal(t, forbiddenErr, err)
				assert.True(t, isCheckDisabled(ctx))
			})

			t.Run("success: allowed (even though context disabled)", func(t *testing.T) {
				mockFactory.EXPECT().Scope(gomock.Any()).Return(scope)
				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub)
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(objUpdate)
				mockCasbin.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)

				err := g.ForceCheckPerm(ctx, userID, permOrgUpdate, scopeData)
				assert.NoError(t, err)
				assert.True(t, isCheckDisabled(ctx))
			})
		})

		t.Run("HasPermInScope", func(t *testing.T) {
			ctx := Context(context.Background())

			t.Run("error: forbidden (forceCheck=false)", func(t *testing.T) {
				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub)
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(objUpdate)
				mockCasbin.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Return(false, nil)

				err := g.HasPermInScope(ctx, userID, permOrgUpdate, scope)
				assert.Error(t, err)
				assert.Equal(t, forbiddenErr, err)
			})

			t.Run("success: allowed (forceCheck=false)", func(t *testing.T) {
				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub)
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(objUpdate)
				mockCasbin.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)

				err := g.HasPermInScope(ctx, userID, permOrgUpdate, scope)
				assert.NoError(t, err)
				assert.True(t, isCheckDisabled(ctx))
			})

			t.Run("success: allowed (forceCheck=true)", func(t *testing.T) {
				ctxForce := Context(context.Background())
				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub)
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(objUpdate)
				mockCasbin.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)

				err := g.HasPermInScope(ctxForce, userID, permOrgUpdate, scope, true)
				assert.NoError(t, err)
				assert.False(t, isCheckDisabled(ctxForce))
			})
		})

		t.Run("sanitizeRolePolicies", func(t *testing.T) {
			t.Run("no error", func(t *testing.T) {
				mockFactory.EXPECT().Scope(gomock.Any()).Return(scope)
				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(rolePolicy, nil)

				_, err := g.sanitizeRolePolicies(sanitizeRolePolicies{scopeData: scopeData, casbinPolicies: [][]string{rolePolicy.ToCasbin(userSub)}})
				assert.NoError(t, err, "sanitize role casbinPolicies should be success")
			})

			t.Run("error: not found", func(t *testing.T) {
				mockFactory.EXPECT().Scope(gomock.Any()).Return(scope)
				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(nil, mockErr)

				_, err := g.sanitizeRolePolicies(sanitizeRolePolicies{scopeData: scopeData, casbinPolicies: [][]string{rolePolicyUnexpected.ToCasbin(userSub)}})
				assert.Error(t, err, "sanitize role casbinPolicies returns error")
			})
		})

		t.Run("CreateRole", func(t *testing.T) {
			t.Run("error: role policies from casbin", func(t *testing.T) {
				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(nil, mockErr)

				err := g.CreateRole(RoleRequest{Sub: userSub, ScopeData: scopeData, Policies: [][]string{rolePolicy.ToCasbin(userSub)}})
				assert.Error(t, err, "role should not be created")
			})

			t.Run("error: sanitize", func(t *testing.T) {
				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(nil, mockErr)

				err := g.CreateRole(RoleRequest{Sub: userSub, ScopeData: scopeData, Policies: [][]string{rolePolicyUnexpected.ToCasbin(userSub)}})
				assert.Error(t, err, "role should not be created")
			})

			t.Run("error: add casbin policies", func(t *testing.T) {
				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(rolePolicy, nil)
				mockFactory.EXPECT().Scope(gomock.Any()).Return(scope)
				mockCasbin.EXPECT().AddPoliciesEx(gomock.Any()).Return(false, mockErr)

				err := g.CreateRole(RoleRequest{Sub: roleSub, ScopeData: scopeData, Policies: [][]string{}})
				assert.Error(t, err, "role should not be created")
			})

			t.Run("success", func(t *testing.T) {
				mockCasbin.EXPECT().AddPoliciesEx(gomock.Any()).Return(true, nil)

				err := g.CreateRole(RoleRequest{Sub: roleSub, ScopeData: scopeData, Policies: [][]string{rolePolicy.ToCasbin(roleSub)}})
				assert.NoError(t, err, "role should be created")
			})
		})

		t.Run("UpdateRole", func(t *testing.T) {
			t.Run("error: empty user id", func(t *testing.T) {
				err := g.UpdateRole(context.Background(), "", RoleRequest{})
				assert.Error(t, err, "user id must not be empty")
			})

			t.Run("error: RolePoliciesFromCasbin (new policies)", func(t *testing.T) {
				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(nil, mockErr).Times(lenRolePoliciesToAdd)

				err := g.UpdateRole(context.Background(), userID, RoleRequest{Sub: roleSub, ScopeData: scopeData, Policies: casbinPoliciesToAdd})
				assert.Error(t, err)
				assert.Equal(t, mockErr, err)
			})

			t.Run("error: sanitize", func(t *testing.T) {
				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(rolePolicyUnexpected, nil).Times(lenRolePoliciesToAdd)

				err := g.UpdateRole(context.Background(), userID, RoleRequest{Sub: roleSub, ScopeData: scopeData, Policies: casbinPoliciesToAdd})
				assert.Error(t, err)
			})

			t.Run("error: GetFilteredPolicy", func(t *testing.T) {
				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(rolePolicy, nil).Times(lenRolePoliciesToAdd)
				mockFactory.EXPECT().Scope(gomock.Any()).Return(scope).Times(lenRolePoliciesToAdd)
				mockCasbin.EXPECT().GetFilteredPolicy(gomock.Any(), gomock.Any()).Return(nil, mockErr)

				err := g.UpdateRole(context.Background(), userID, RoleRequest{Sub: roleSub, ScopeData: scopeData, Policies: casbinPoliciesToAdd})
				assert.Error(t, err)
				assert.Equal(t, mockErr, err)
			})

			t.Run("error: RolePoliciesFromCasbin (existing policies)", func(t *testing.T) {
				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(rolePolicy2, nil).Times(lenRolePoliciesToAdd)
				mockFactory.EXPECT().Scope(gomock.Any()).Return(scope)
				mockCasbin.EXPECT().GetFilteredPolicy(gomock.Any(), gomock.Any()).Return(casbinPoliciesToAdd, nil)
				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(nil, mockErr).Times(lenRolePoliciesToAdd)

				err := g.UpdateRole(context.Background(), userID, RoleRequest{Sub: roleSub, ScopeData: scopeData, Policies: casbinPoliciesToAdd})
				assert.Error(t, err)
				assert.Equal(t, mockErr, err)
			})

			t.Run("error: RemoveFilteredPolicy", func(t *testing.T) {
				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(rolePolicy, nil)
				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(rolePolicy2, nil)
				mockFactory.EXPECT().Scope(gomock.Any()).Return(scope).Times(lenRolePoliciesToAdd)
				mockFactory.EXPECT().Scope(gomock.Any()).Return(scope).Times(lenRolePoliciesToAdd)
				mockCasbin.EXPECT().GetFilteredPolicy(gomock.Any(), gomock.Any()).Return(casbinPoliciesToAdd, nil)

				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(rolePolicy, nil)
				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(rolePolicy2, nil)

				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub)
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(objUpdate)
				mockCasbin.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)

				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub)
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(objAll)
				mockCasbin.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)

				mockCasbin.EXPECT().RemoveFilteredPolicy(gomock.Any(), gomock.Any()).Return(false, forbiddenErr)

				err := g.UpdateRole(context.Background(), userID, RoleRequest{Sub: roleSub, ScopeData: scopeData, Policies: casbinPoliciesToAdd})
				assert.Error(t, err)
				assert.Equal(t, forbiddenErr, err)
			})

			t.Run("error: AddPoliciesEx", func(t *testing.T) {
				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(rolePolicy, nil)
				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(rolePolicy2, nil)
				mockFactory.EXPECT().Scope(gomock.Any()).Return(scope).Times(lenRolePoliciesToAdd)
				mockCasbin.EXPECT().GetFilteredPolicy(gomock.Any(), gomock.Any()).Return(casbinPoliciesToAdd, nil)

				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(rolePolicy, nil)
				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(rolePolicy2, nil)

				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub)
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(objUpdate)
				mockCasbin.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)

				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub)
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(objAll)
				mockCasbin.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil)

				mockCasbin.EXPECT().RemoveFilteredPolicy(gomock.Any(), gomock.Any()).Return(true, nil)
				mockCasbin.EXPECT().AddPoliciesEx(gomock.Any()).Return(false, forbiddenErr)

				err := g.UpdateRole(context.Background(), userID, RoleRequest{Sub: roleSub, ScopeData: scopeData, Policies: casbinPoliciesToAdd})
				assert.Error(t, err)
				assert.Equal(t, forbiddenErr, err)
			})

			t.Run("success", func(t *testing.T) {
				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(rolePolicy, nil)
				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(rolePolicy2, nil)
				mockFactory.EXPECT().Scope(gomock.Any()).Return(scope).AnyTimes()
				mockCasbin.EXPECT().GetFilteredPolicy(gomock.Any(), gomock.Any()).Return(casbinPoliciesToAdd, nil)

				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(rolePolicy, nil)
				mockFactory.EXPECT().RolePolicyFromCasbin(gomock.Any()).Return(rolePolicy2, nil)

				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub).Times(2)
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(objUpdate)
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(objAll)
				mockCasbin.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil).Times(2)

				mockCasbin.EXPECT().RemoveFilteredPolicy(gomock.Any(), gomock.Any()).Return(true, nil)
				mockCasbin.EXPECT().AddPoliciesEx(gomock.Any()).Return(true, nil)

				err := g.UpdateRole(context.Background(), userID, RoleRequest{Sub: roleSub, ScopeData: scopeData, Policies: casbinPoliciesToAdd})
				assert.NoError(t, err)
			})
		})

		t.Run("DeleteRole", func(t *testing.T) {
			t.Run("error: empty user id", func(t *testing.T) {
				err := g.DeleteRole(context.Background(), "", roleSub)
				assert.Error(t, err)
				assert.Equal(t, errors.New("user id must not be empty"), err)
			})

			t.Run("error: hasAllSubjectPerms", func(t *testing.T) {
				mockCasbin.EXPECT().GetImplicitPermissionsForUser(gomock.Any()).Return(nil, mockErr)

				err := g.DeleteRole(context.Background(), userID, roleSub)
				assert.Error(t, err)
				assert.Equal(t, mockErr, err)
			})

			t.Run("error: RemoveFilteredPolicy", func(t *testing.T) {
				mockCasbin.EXPECT().GetImplicitPermissionsForUser(gomock.Any()).Return(policySlice, nil)
				mockFactory.EXPECT().RolePoliciesFromCasbin(gomock.Any()).Return(rolePoliciesToAdd, nil)

				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub).AnyTimes()
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(objAll).AnyTimes()
				mockCasbin.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

				mockCasbin.EXPECT().RemoveFilteredPolicy(gomock.Any(), gomock.Any()).Return(false, mockErr)

				err := g.DeleteRole(context.Background(), userID, roleSub)
				assert.Error(t, err)
				assert.Equal(t, mockErr, err)
			})

			t.Run("error: RemoveFilteredGroupingPolicy", func(t *testing.T) {
				mockCasbin.EXPECT().GetImplicitPermissionsForUser(gomock.Any()).Return(nil, nil)
				mockFactory.EXPECT().RolePoliciesFromCasbin(gomock.Any()).Return(rolePoliciesToAdd, nil)

				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub).AnyTimes()
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(objAll).AnyTimes()
				mockCasbin.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

				mockCasbin.EXPECT().RemoveFilteredPolicy(gomock.Any(), gomock.Any()).Return(true, nil)
				mockCasbin.EXPECT().RemoveFilteredGroupingPolicy(gomock.Any(), gomock.Any()).Return(false, mockErr)

				err := g.DeleteRole(context.Background(), userID, roleSub)
				assert.Error(t, err)
				assert.Equal(t, mockErr, err)
			})

			t.Run("success", func(t *testing.T) {
				mockCasbin.EXPECT().GetImplicitPermissionsForUser(gomock.Any()).Return(nil, nil)
				mockFactory.EXPECT().RolePoliciesFromCasbin(gomock.Any()).Return(rolePoliciesToAdd, nil)

				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub).AnyTimes()
				mockFactory.EXPECT().Object(gomock.Any(), gomock.Any()).Return(objAll).AnyTimes()
				mockCasbin.EXPECT().Enforce(gomock.Any(), gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

				mockCasbin.EXPECT().RemoveFilteredPolicy(gomock.Any(), gomock.Any()).Return(true, nil)
				mockCasbin.EXPECT().RemoveFilteredGroupingPolicy(gomock.Any(), gomock.Any()).Return(true, nil)

				err := g.DeleteRole(context.Background(), userID, roleSub)
				assert.NoError(t, err)
			})
		})

		t.Run("AssignRoles", func(t *testing.T) {
			t.Run("error: AddGroupingPoliciesEx", func(t *testing.T) {
				mockFactory.EXPECT().GroupPolicy(gomock.Any(), gomock.Any()).Return(groupPolicy).Times(lenRolePoliciesToAdd)
				mockCasbin.EXPECT().AddGroupingPoliciesEx(gomock.Any()).Return(false, mockErr)

				err := g.AssignRoles(userSub, roleSub)
				assert.Error(t, err)
				assert.Equal(t, mockErr, err)
			})

			t.Run("success", func(t *testing.T) {
				mockFactory.EXPECT().GroupPolicy(gomock.Any(), gomock.Any()).Return(groupPolicy)
				mockCasbin.EXPECT().AddGroupingPoliciesEx(gomock.Any()).Return(true, nil)

				err := g.AssignRoles(userSub, roleSub)
				assert.NoError(t, err)
			})
		})

		t.Run("RevokeRoles", func(t *testing.T) {
			t.Run("error: RemoveGroupingPolicy", func(t *testing.T) {
				mockCasbin.EXPECT().RemoveGroupingPolicy(gomock.Any()).Return(false, mockErr)

				err := g.RevokeRoles(userSub, roleSub)
				assert.Error(t, err)
				assert.Equal(t, mockErr, err)
			})

			t.Run("success: with roles", func(t *testing.T) {
				mockFactory.EXPECT().GroupPolicy(gomock.Any(), gomock.Any()).Return(groupPolicy)
				mockCasbin.EXPECT().RemoveGroupingPolicy(gomock.Any()).Return(true, nil)

				err := g.RevokeRoles(userSub, roleSub)
				assert.NoError(t, err)
			})

			t.Run("error: RemoveFilteredGroupingPolicy", func(t *testing.T) {
				mockCasbin.EXPECT().RemoveFilteredGroupingPolicy(gomock.Any(), gomock.Any()).Return(false, mockErr)

				err := g.RevokeRoles(userSub)
				assert.Error(t, err)
				assert.Equal(t, mockErr, err)
			})

			t.Run("success: without roles", func(t *testing.T) {
				mockCasbin.EXPECT().RemoveFilteredGroupingPolicy(gomock.Any(), gomock.Any()).Return(true, nil)

				err := g.RevokeRoles(userSub)
				assert.NoError(t, err)
			})
		})

		t.Run("RemoveUserPerms", func(t *testing.T) {
			t.Run("error", func(t *testing.T) {
				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub).AnyTimes()
				mockCasbin.EXPECT().RemoveFilteredGroupingPolicy(gomock.Any(), gomock.Any()).Return(false, mockErr)

				err := g.RemoveUserPerms(userID)
				assert.Error(t, err)
				assert.Equal(t, mockErr, err)
			})

			t.Run("success", func(t *testing.T) {
				mockFactory.EXPECT().SubjectUser(gomock.Any()).Return(userSub).AnyTimes()
				mockCasbin.EXPECT().RemoveFilteredGroupingPolicy(gomock.Any(), gomock.Any()).Return(true, nil)

				err := g.RemoveUserPerms(userID)
				assert.NoError(t, err)
			})
		})

		t.Run("GetFilteredPolicies", func(t *testing.T) {
			t.Run("error: GetPolicy", func(t *testing.T) {
				mockCasbin.EXPECT().GetPolicy().Return(nil, mockErr)

				_, err := g.GetFilteredPolicies(func(pol contracts.Policy) bool { return true })
				assert.Error(t, err)
				assert.Equal(t, mockErr, err)
			})

			t.Run("success", func(t *testing.T) {
				policies := [][]string{{"sub", "obj", "act", "eff"}}
				mockCasbin.EXPECT().GetPolicy().Return(policies, nil)
				mockFactory.EXPECT().PolicyFromCasbin(gomock.Any()).Return(nil, nil)

				result, err := g.GetFilteredPolicies(func(pol contracts.Policy) bool { return true })
				assert.NoError(t, err)
				assert.Equal(t, policies, result)
			})
		})

		t.Run("RemoveObjectPerms", func(t *testing.T) {
			t.Run("error: GetFilteredPolicies", func(t *testing.T) {
				mockCasbin.EXPECT().GetPolicy().Return(nil, mockErr)

				err := g.RemoveObjectPerms("object", "objectID")
				assert.Error(t, err)
				assert.Equal(t, mockErr, err)
			})

			t.Run("error: RemovePolicies", func(t *testing.T) {
				mockCasbin.EXPECT().GetPolicy().Return(policySlice, nil)
				mockFactory.EXPECT().PolicyFromCasbin(gomock.Any()).Return(policy, nil)
				mockCasbin.EXPECT().RemovePolicies(gomock.Any()).Return(false, mockErr)

				err := g.RemoveObjectPerms("object", "objectID")
				assert.Error(t, err)
				assert.Equal(t, mockErr, err)
			})

			t.Run("success", func(t *testing.T) {
				mockCasbin.EXPECT().GetPolicy().Return(policySlice, nil)
				mockFactory.EXPECT().PolicyFromCasbin(gomock.Any()).Return(policy, nil)
				mockCasbin.EXPECT().RemovePolicies(gomock.Any()).Return(true, nil)

				err := g.RemoveObjectPerms("object", "objectID")
				assert.NoError(t, err)
			})
		})

		t.Run("RemoveScopePerms", func(t *testing.T) {
			t.Run("error: GetFilteredPolicies", func(t *testing.T) {
				mockCasbin.EXPECT().GetPolicy().Return(nil, mockErr)

				err := g.RemoveScopePerms(scope)
				assert.Error(t, err)
				assert.Equal(t, mockErr, err)
			})

			t.Run("error: RemovePolicies", func(t *testing.T) {
				mockCasbin.EXPECT().GetPolicy().Return(policySlice, nil)
				mockFactory.EXPECT().PolicyFromCasbin(gomock.Any()).Return(policy, nil)
				mockCasbin.EXPECT().RemovePolicies(gomock.Any()).Return(false, mockErr)

				err := g.RemoveScopePerms(scope)
				assert.Error(t, err)
				assert.Equal(t, mockErr, err)
			})

			t.Run("success", func(t *testing.T) {
				mockCasbin.EXPECT().GetPolicy().Return(policySlice, nil)
				mockFactory.EXPECT().PolicyFromCasbin(gomock.Any()).Return(policy, nil)
				mockCasbin.EXPECT().RemovePolicies(gomock.Any()).Return(true, nil)

				err := g.RemoveScopePerms(scope)
				assert.NoError(t, err)
			})
		})

		t.Run("GetPermsByObject", func(t *testing.T) {
			t.Run("admin: true", func(t *testing.T) {
				perms, err := g.GetPermsByObject(GetPermsByObjectRequest{Admin: true, Object: common.EntityObjectOrg.String()})
				assert.NoError(t, err)
				assert.NotEmpty(t, perms)
			})

			t.Run("admin: false", func(t *testing.T) {
				perms, err := g.GetPermsByObject(GetPermsByObjectRequest{Admin: false, Object: common.EntityObjectOrg.String()})
				assert.NoError(t, err)
				assert.NotEmpty(t, perms)
			})
		})
	})

}
