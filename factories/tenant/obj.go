package tenant

import (
	"fmt"
	"strings"

	"github.com/uagolang/guard/common"
	"github.com/uagolang/guard/common/contracts"
	"github.com/uagolang/guard/utils"
)

// object for the casbin model
type object struct {
	tenantID       string
	entityObject   common.EntityObject
	entityObjectID string
}

// NewObject accepts scopes in order: tenant, entityObject, entityObjectID
// If any scope excepts entityObjectID is empty, it will be replaced with "*" (wildcard).
func newObject(scopes ...string) *object {
	return &object{
		tenantID:     utils.SliceElem(scopes, 0, common.Wildcard),
		entityObject: utils.SliceElem([]common.EntityObject{}, 0, common.EntityObjectAll),
	}
}

// NewObjFromCasbin accepts an object string in the casbin format "/tenantID/entityObject/entityObjectID".
// Returns a pointer to an object with the given scopes.
func NewObjFromCasbin(s string) (contracts.Object, error) {
	list := strings.Split(strings.TrimPrefix(s, "/"), "/")
	if len(list) != 3 {
		return nil, common.ErrUnknownType("casbin object", s)
	}
	return newObject(list...), nil
}

// ToCasbin returns the object string in the casbin format "/tenantID/entityObject/entityObjectID".
func (o *object) ToCasbin() string {
	return fmt.Sprintf("/%s/%s/%s", o.tenantID, o.entityObject, o.entityObjectID)
}

func (o *object) SetScope(scope contracts.Scope) contracts.Object {
	o.tenantID = scope.Get(ScopeDataTenantIDName)
	return o
}

func (o *object) GetScope() contracts.Scope {
	return newScope(WithData(map[string]string{
		ScopeDataTenantIDName: o.tenantID,
	}))
}

func (o *object) SetPerm(perm any) contracts.Object {
	p, ok := perm.(common.Perm)
	if ok {
		o.entityObject = common.EntityObject(p.GetObject())
		if p.GetObjectID() != "" {
			o.entityObjectID = p.GetObjectID()
		}
	}

	return o
}

func (o *object) GetPerm(list any, obj, objID, action string) (any, error) {
	permsList, ok := list.([]common.Perm)
	if !ok {
		return nil, common.ErrUnknownType("perms list", "")
	}

	return common.GetPerm(permsList, obj, objID, action)
}
