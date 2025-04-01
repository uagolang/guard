package perms

import (
	"fmt"

	"github.com/uagolang/guard/common"
)

type Lister interface {
	All() *common.Perm
	List() *common.Perm
	Get() *common.Perm
	Create() *common.Perm
	Update() *common.Perm
	Delete() *common.Perm
	Perms() []common.Perm
}

var listers = []Lister{
	All,
	User,
	Org,
	OrgUser,
	Role,
}

type permsLister struct {
	obj            common.EntityObject
	objectSingular string
	objectPlural   string
}

func NewPermsLister(object common.EntityObject, objectSingular, objectPlural string) Lister {
	return &permsLister{
		obj:            object,
		objectSingular: objectSingular,
		objectPlural:   objectPlural,
	}
}

func (o *permsLister) All() *common.Perm {
	return &common.Perm{
		Object: o.obj,
		Action: common.Wildcard,
		Name:   "All",
		Desc:   fmt.Sprintf("Full access to %s", o.objectPlural),
	}
}

func (o *permsLister) List() *common.Perm {
	return &common.Perm{
		Object: o.obj,
		Action: common.ActionList,
		Name:   "List",
		Desc:   fmt.Sprintf("View the list of %s", o.objectPlural),
	}
}

func (o *permsLister) Get() *common.Perm {
	return &common.Perm{
		Object:   o.obj,
		ObjectID: common.Wildcard,
		Action:   common.ActionGet,
		Name:     "Get",
		Desc:     fmt.Sprintf("Get details of %s", o.objectSingular),
	}
}

func (o *permsLister) Create() *common.Perm {
	return &common.Perm{
		Object: o.obj,
		Action: common.ActionCreate,
		Name:   "Create",
		Desc:   fmt.Sprintf("Create %s", o.objectPlural),
	}
}

func (o *permsLister) Update() *common.Perm {
	return &common.Perm{
		Object:   o.obj,
		ObjectID: common.Wildcard,
		Action:   common.ActionUpdate,
		Name:     "Update",
		Desc:     fmt.Sprintf("Update %s", o.objectSingular),
	}
}

func (o *permsLister) Delete() *common.Perm {
	return &common.Perm{
		Object:   o.obj,
		ObjectID: common.Wildcard,
		Action:   common.ActionDelete,
		Name:     "Delete",
		Desc:     fmt.Sprintf("Delete %s", o.objectSingular),
	}
}

func (o *permsLister) Perms() []common.Perm {
	return []common.Perm{
		*o.All(),
		*o.List(),
		*o.Get(),
		*o.Create(),
		*o.Update(),
		*o.Delete(),
	}
}
