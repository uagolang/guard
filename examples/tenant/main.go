package main

import (
	"context"
	"log"

	"github.com/casbin/casbin/v2"

	"github.com/uagolang/guard"
	"github.com/uagolang/guard/common"
	"github.com/uagolang/guard/common/contracts"
	"github.com/uagolang/guard/examples/tenant/rbac"
	"github.com/uagolang/guard/factories/tenant"
	"github.com/uagolang/guard/perms"
)

func main() {
	ctx := guard.Context(context.Background())
	ctx2 := guard.Context(context.Background())
	enforcer, err := casbin.NewEnforcer("./models/tenant.conf", "./examples/tenant/policies.csv")
	if err != nil {
		log.Fatal(err)
	}

	userID := "user1"
	userID3 := "user3"
	orgID := "org1"
	allEntityObjects := append(common.EntityObjects, rbac.Objects...)
	allPerms := append(perms.AllPerms, rbac.AllPerms...)
	allActions := append(common.Actions, rbac.Actions...)

	g := guard.New(
		guard.WithFactory(tenant.NewFactory(allPerms...)),
		guard.WithEnforcer(enforcer),
		guard.WithPerms(allPerms),                 // standard + custom
		guard.WithActions(allActions),             // standard + custom
		guard.WithEntityObjects(allEntityObjects), // standard + custom
		guard.WithScopedObjects(map[contracts.ScopeLevel][]common.EntityObject{
			contracts.ScopeLevelSystem: allEntityObjects,
			contracts.ScopeLevelTenant: {
				rbac.EntityObjectApp,
			},
		}),
	)

	err = g.HasPerm(ctx, userID, perms.Org.Update().WithID(orgID), orgID)
	if err != nil {
		log.Fatal(err)
	} else {
		log.Println("has access")
	}

	err = g.HasPerm(ctx2, userID3, perms.Org.Update().WithID(orgID), orgID)
	if err != nil {
		log.Fatal(err)
	} else {
		log.Println("has access")
	}
}
