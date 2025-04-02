package common

import (
	"github.com/uagolang/guard/utils"
)

type EntityObject string

const (
	EntityObjectAll      EntityObject = "*"
	EntityObjectUser     EntityObject = "User"
	EntityObjectOrg      EntityObject = "Org"
	EntityObjectOrgUser  EntityObject = "User"
	EntityObjectPerm     EntityObject = "Permission"
	EntityObjectRole     EntityObject = "Role"
	EntityObjectRoleUser EntityObject = "Role User"
)

func (obj EntityObject) String() string {
	return string(obj)
}

func (obj EntityObject) List() any {
	return EntityObjects
}

func (obj EntityObject) Strings() []string {
	return utils.Map(EntityObjects, func(item EntityObject, _ int) string {
		return item.String()
	})
}

func (obj EntityObject) Validate() error {
	if !utils.Contains(EntityObjects, obj) {
		return ErrUnknownType("entity object", obj.String())
	}

	return nil
}

var EntityObjects = []EntityObject{
	EntityObjectUser, EntityObjectOrg, EntityObjectOrgUser, EntityObjectPerm, EntityObjectRole, EntityObjectRoleUser,
}
