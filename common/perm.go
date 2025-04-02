package common

import (
	"strings"

	"github.com/uagolang/guard/contracts"
	"github.com/uagolang/guard/utils"
)

// Permission describes what can be done with an object.
// action could apply to a specific object or to all objects of a type.
// e.g. "create" applies to a type of object, as there is no id to specify yet,
// but "delete" could apply to a specific object - when id is specified, or to all objects of a type - when id is "*" (wildcard).
type Permission struct {
	// Name returns user-friendly name to display to clients
	Name string `json:"name" form:"name"`
	// Desc to display to clients
	Desc string `json:"desc" form:"desc"`
	// Object is a noun slug of an object
	Object EntityObject `json:"object" form:"object" validate:"required"`
	// ObjectID is an id of a specific object, or wildcard "*", or empty if not applicable
	ObjectID string `json:"object_id" form:"object_id" validate:"omitempty"`
	// Action is a verb slug of an action
	Action Action `json:"action" form:"action" validate:"required"`
	// Admin is an attribute that marks permissions to be used only in backoffice (admin)
	Admin bool `json:"-"`
}

func (p *Permission) IsAdmin() bool {
	return p.Admin
}

func (p *Permission) GetAction() string {
	return p.Action.String()
}

func (p *Permission) GetObject() string {
	return p.Object.String()
}

// WithID specify a concrete object ID if the permission allows it.
func (p *Permission) WithID(id string) contracts.Perm {
	if p.ObjectID == Wildcard && id != "" {
		p.ObjectID = id
	}

	return p
}

// GetObjectID get object ID if applicable and specified.
func (p *Permission) GetObjectID() string {
	if p.ObjectID == Wildcard || p.ObjectID == "" {
		return ""
	}

	return p.ObjectID
}

func (p *Permission) GetMidSentenceDescription() string {
	return strings.ToLower(p.Desc[:1]) + p.Desc[1:]
}

func (p *Permission) GetDeniedDescription() string {
	description := p.GetMidSentenceDescription()
	description = strings.ReplaceAll(description, " an ", " this ")
	description = strings.ReplaceAll(description, " a ", " this ")

	return description
}

func GetPerm(perms []contracts.Perm, obj, objID, action string) (contracts.Perm, error) {
	p, found := utils.Find(perms, func(perm contracts.Perm) bool {
		return perm.GetObject() == obj && perm.GetAction() == action
	})
	if !found {
		return nil, ErrNotFoundPerm(obj, action)
	}

	return p.WithID(objID), nil
}
