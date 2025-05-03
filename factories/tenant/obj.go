package tenant

import (
	"fmt"
	"strings"

	"github.com/uagolang/guard/common"
	"github.com/uagolang/guard/contracts"
	"github.com/uagolang/guard/utils"
)

// Object for the casbin model
type Object struct {
	TenantID       string
	EntityObject   common.EntityObject
	EntityObjectID string
}

// NewObject accepts scopes in order: TenantID, EntityObject, EntityObjectID
// If any Scope excepting EntityObjectID is empty, it will be replaced with "*" (wildcard).
func NewObject(scopes ...string) *Object {
	return &Object{
		TenantID:       utils.SliceElem(scopes, 0, common.Wildcard),
		EntityObject:   common.EntityObject(utils.SliceElem(scopes, 1, common.EntityObjectAll.String())),
		EntityObjectID: utils.SliceElem(scopes, 3, common.Wildcard),
	}
}

// NewObjFromCasbin accepts an Object string in the casbin format "/TenantID/EntityObject/EntityObjectID".
// Returns a pointer to an Object with the given scopes.
func NewObjFromCasbin(s string) (contracts.Object, error) {
	list := strings.Split(strings.TrimPrefix(s, "/"), "/")
	if len(list) != 3 {
		return nil, common.ErrUnknownType("casbin Object", s)
	}
	return NewObject(list...), nil
}

// ToCasbin returns the Object string in the casbin format "/TenantID/EntityObject/EntityObjectID".
func (o *Object) ToCasbin() string {
	return fmt.Sprintf("/%s/%s/%s", o.TenantID, o.EntityObject, o.EntityObjectID)
}

func (o *Object) SetScope(scope contracts.Scope) contracts.Object {
	o.TenantID = scope.Get(ScopeDataTenantIDName)
	return o
}

func (o *Object) GetScope() contracts.Scope {
	return newScope(WithData(contracts.ScopeData{
		ScopeDataTenantIDName: o.TenantID,
	}))
}

func (o *Object) SetPerm(perm contracts.Perm) contracts.Object {
	p, ok := perm.(contracts.Perm)
	if ok {
		o.EntityObject = common.EntityObject(p.GetObject())
		if p.GetObjectID() != "" {
			o.EntityObjectID = p.GetObjectID()
		}
	}

	return o
}

func (o *Object) GetPerm(list []contracts.Perm, action string) (contracts.Perm, error) {
	return common.GetPerm(list, o.EntityObject.String(), o.EntityObjectID, action)
}
