# Guard

Guard is a Go library that helps implement Role-Based Access Control (RBAC) using [Casbin](https://github.com/casbin/casbin). It provides a flexible and extensible way to manage permissions and access control in your Go applications.

## Table of Contents

- [Installation](#installation)
- [Overview](#overview)
- [Usage Examples](#usage-examples)
- [Using Existing Factories](#using-existing-factories)
- [Creating Custom Factories](#creating-custom-factories)
- [API Reference](#api-reference)

## Installation

```bash
go get github.com/uagolang/guard
```

## Overview

Guard is built on top of Casbin and provides a higher-level API for managing RBAC in your applications. It uses factories to create various components of the RBAC system, such as subjects (users, roles, groups), objects (resources), and policies (access rules).

Key features:
- Multi-tenant support
- Hierarchical roles
- Fine-grained permission control
- Extensible through custom factories

## Usage Examples

### Basic Setup

```go
package main

import (
	"context"
	"log"

	"github.com/casbin/casbin/v2"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"

	"github.com/uagolang/guard"
	"github.com/uagolang/guard/common"
	"github.com/uagolang/guard/factories/tenant"
)

func main() {
	// Create a context
	ctx := guard.Context(context.Background())

	// Initialize Casbin with a file adapter
	a := fileadapter.NewAdapter("./policies.csv")
	enforcer, err := casbin.NewEnforcer("./models/tenant.conf", a)
	if err != nil {
		log.Fatal(err)
	}

	// Load policies
	err = enforcer.LoadPolicy()
	if err != nil {
		log.Fatal(err)
	}

	// Create a Guard instance with the tenant factory
	g := guard.New(tenant.NewFactory(), enforcer)

	// Define scope data (e.g., tenant ID)
	tenantID := "org1"
	scopeData := contracts.ScopeData{
		tenant.ScopeDataTenantIDName: tenantID,
	}

	// Check if a user has permission
	userID := "user1"
	err = g.HasPerm(ctx, userID, common.Org.Update().WithID(tenantID), scopeData)
	if err != nil {
		log.Println("Access denied:", err)
	} else {
		log.Println("Access granted")
	}
}
```

### Creating and Assigning Roles

```go
// Create an admin role
adminRoleSub := tenant.NewSubjectRole(tenantID, "admin")
err = g.CreateRole(guard.RoleRequest{
	Sub:       adminRoleSub,
	ScopeData: scopeData,
	Policies: [][]string{
		{"1/org1/org_admin", "/org1/*/*", "*", "allow"},
	},
})
if err != nil {
	log.Fatal(err)
}

// Assign a user to the admin role
err = g.AssignRoles(tenant.NewSubjectUser("user1"), adminRoleSub)
if err != nil {
	log.Fatal(err)
}
```

## Using Existing Factories

Guard comes with pre-built factories that you can use out of the box. The main factory is the `tenant` factory, which provides a multi-tenant RBAC implementation.

### Tenant Factory

The tenant factory is designed for multi-tenant applications where each tenant (organization) has its own set of roles and permissions.

```go
import (
	"github.com/uagolang/guard"
	"github.com/uagolang/guard/factories/tenant"
)

// Create a Guard instance with the tenant factory
g := guard.New(tenant.NewFactory(), enforcer)

// Create a scope with tenant ID
scopeData := contracts.ScopeData{
	tenant.ScopeDataTenantIDName: "org1",
}

// Create subjects (users, roles, groups)
userSub := tenant.NewSubjectUser("user1")
roleSub := tenant.NewSubjectRole("org1", "admin")
groupSub := tenant.NewSubjectGroup("org1", "team1")

// Create objects and check permissions
err = g.HasPerm(ctx, "user1", common.Org.Update().WithID("org1"), scopeData)
```

## Creating Custom Factories

You can create your own factories to customize the behavior of Guard for your specific needs. A factory must implement the `contracts.Factory` interface:

```go
type Factory interface {
	Scope(data ScopeData) Scope
	SubjectUser(id string) Subject
	SubjectRole(tenantID, id string) Subject
	SubjectGroup(tenantID, id string) Subject
	Object(s Scope, p Perm) Object
	GroupPolicy(sub, role Subject) GroupPolicy
	PolicyFromCasbin(p []string) (Policy, error)
	RolePolicyFromCasbin(p []string) (RolePolicy, error)
	RolePoliciesFromCasbin(p [][]string) ([]RolePolicy, error)
	GroupPolicyFromCasbin(p []string) (GroupPolicy, error)
}
```

### Example Custom Factory

Here's a simplified example of how to create a custom factory:

```go
package myfactory

import (
	"github.com/uagolang/guard/contracts"
)

type factory struct {
	perms []contracts.Perm
}

func NewFactory(perms ...contracts.Perm) contracts.Factory {
	return &factory{perms: perms}
}

// Implement all the methods required by the Factory interface
func (f *factory) Scope(data contracts.ScopeData) contracts.Scope {
	// Your implementation
}

func (f *factory) SubjectUser(id string) contracts.Subject {
	// Your implementation
}

// ... implement all other methods
```

### Extending Existing Factories

You can also extend existing factories to add custom behavior:

```go
package myextendedtenant

import (
	"github.com/uagolang/guard/contracts"
	"github.com/uagolang/guard/factories/tenant"
)

type extendedFactory struct {
	tenant.Factory
	// Additional fields
}

func NewFactory() contracts.Factory {
	base := tenant.NewFactory()
	return &extendedFactory{
		Factory: base,
		// Initialize additional fields
	}
}

// Override methods as needed
func (f *extendedFactory) SubjectUser(id string) contracts.Subject {
	// Custom implementation
}
```

## API Reference

For a complete API reference, please refer to the [GoDoc documentation](https://pkg.go.dev/github.com/uagolang/guard).

Key components:
- `Guard`: The main struct that provides methods for permission checking and role management
- `Factory`: Interface for creating RBAC components
- `Subject`: Interface for users, roles, and groups
- `Object`: Interface for resources that are protected by permissions
- `Perm`: Interface for permissions
- `Scope`: Interface for defining the scope of permissions
