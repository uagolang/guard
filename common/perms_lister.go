package common

import (
	"fmt"

	"github.com/uagolang/guard/contracts"
)

type Lister interface {
	All() *Permission
	List() *Permission
	Get() *Permission
	Create() *Permission
	Update() *Permission
	Delete() *Permission
	Perms() []contracts.Perm
}

var listers = []Lister{
	All,
	User,
	Org,
	OrgUser,
	Role,
}

type permsLister struct {
	obj            EntityObject
	objectSingular string
	objectPlural   string
}

func NewPermsLister(object EntityObject, objectSingular, objectPlural string) Lister {
	return &permsLister{
		obj:            object,
		objectSingular: objectSingular,
		objectPlural:   objectPlural,
	}
}

func (o *permsLister) All() *Permission {
	return &Permission{
		Object: o.obj,
		Action: Wildcard,
		Name:   "All",
		Desc:   fmt.Sprintf("Full access to %s", o.objectPlural),
	}
}

func (o *permsLister) List() *Permission {
	return &Permission{
		Object: o.obj,
		Action: ActionList,
		Name:   "List",
		Desc:   fmt.Sprintf("View the list of %s", o.objectPlural),
	}
}

func (o *permsLister) Get() *Permission {
	return &Permission{
		Object:   o.obj,
		ObjectID: Wildcard,
		Action:   ActionGet,
		Name:     "Get",
		Desc:     fmt.Sprintf("Get details of %s", o.objectSingular),
	}
}

func (o *permsLister) Create() *Permission {
	return &Permission{
		Object: o.obj,
		Action: ActionCreate,
		Name:   "Create",
		Desc:   fmt.Sprintf("Create %s", o.objectPlural),
	}
}

func (o *permsLister) Update() *Permission {
	return &Permission{
		Object:   o.obj,
		ObjectID: Wildcard,
		Action:   ActionUpdate,
		Name:     "Update",
		Desc:     fmt.Sprintf("Update %s", o.objectSingular),
	}
}

func (o *permsLister) Delete() *Permission {
	return &Permission{
		Object:   o.obj,
		ObjectID: Wildcard,
		Action:   ActionDelete,
		Name:     "Delete",
		Desc:     fmt.Sprintf("Delete %s", o.objectSingular),
	}
}

func (o *permsLister) Perms() []contracts.Perm {
	return []contracts.Perm{
		o.All(),
		o.List(),
		o.Get(),
		o.Create(),
		o.Update(),
		o.Delete(),
	}
}
