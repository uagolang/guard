package main

import (
	"context"
	"log"

	"github.com/casbin/casbin/v2"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"

	"github.com/uagolang/guard"
	"github.com/uagolang/guard/common"
	"github.com/uagolang/guard/contracts"
	"github.com/uagolang/guard/examples/tenant/rbac"
	factorytenant "github.com/uagolang/guard/factories/tenant"
)

func main() {
	ctx := guard.Context(context.Background())
	ctx2 := guard.Context(context.Background())
	a := fileadapter.NewAdapter("./examples/tenant/policies.csv")
	enforcer, err := casbin.NewEnforcer("./models/tenant.conf", a)
	if err != nil {
		log.Fatal(err)
	}
	err = enforcer.LoadPolicy()
	if err != nil {
		log.Fatal(err)
	}

	orgIDs := []string{"org0", "org1"}
	users := []string{"user0", "user1"}
	roleAdmin := "admin"
	roleMember := "member"
	tenantID := orgIDs[0]

	allEntityObjects := append(common.EntityObjects, rbac.Objects...)
	allPerms := append(common.Perms, rbac.AllPerms...)
	allActions := append(common.Actions, rbac.Actions...)

	g := guard.New(factorytenant.NewFactory(allPerms...), enforcer,
		guard.WithPerms(allPerms...),                 // standard + custom
		guard.WithActions(allActions...),             // standard + custom
		guard.WithEntityObjects(allEntityObjects...), // standard + custom
		guard.WithScopedObjects(map[contracts.ScopeLevel][]common.EntityObject{
			contracts.ScopeLevelSystem: allEntityObjects,
			contracts.ScopeLevelTenant: {
				rbac.EntityObjectApp,
			},
		}),
	)

	scopeData := contracts.ScopeData{
		factorytenant.ScopeDataTenantIDName: tenantID,
	}

	// add org admin role
	adminRoleSub := factorytenant.NewSubjectRole(tenantID, roleAdmin)
	err = g.CreateRole(guard.RoleRequest{
		Sub:       adminRoleSub,
		ScopeData: scopeData,
		Policies: [][]string{
			{"1/org0/org_admin", "/org0/*/*", "*", contracts.PolicyEffectAllow.String()},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// add an org member role
	memberRoleSub := factorytenant.NewSubjectRole(tenantID, roleMember)
	err = g.CreateRole(guard.RoleRequest{
		Sub:       memberRoleSub,
		ScopeData: scopeData,
		Policies: [][]string{
			{"1/org0/org_member", "/org0/App/*", "get", contracts.PolicyEffectAllow.String()},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// add user0 as org admin
	err = g.AssignRoles(factorytenant.NewSubjectUser(users[0]), adminRoleSub)
	if err != nil {
		log.Fatal(err)
	}

	// add user1 as an org member
	err = g.AssignRoles(factorytenant.NewSubjectUser(users[1]), memberRoleSub)
	if err != nil {
		log.Fatal(err)
	}

	err = enforcer.SavePolicy()
	if err != nil {
		log.Fatal(err)
	}

	// has access
	err = g.HasPerm(ctx, users[0], common.Org.Update().WithID(tenantID), scopeData)
	if err != nil {
		log.Println(err)
	} else {
		log.Println("user0:", "has access to update Org")
	}

	// has not access
	err = g.HasPerm(ctx2, users[1], common.Org.Update().WithID(tenantID), scopeData)
	if err != nil {
		log.Println("user1:", err)
	}

	// has access
	err = g.HasPerm(ctx2, users[1], rbac.App.Get().WithID(tenantID), scopeData)
	if err != nil {
		log.Println(err)
	} else {
		log.Println("user1:", "has access to get App")
	}
}
