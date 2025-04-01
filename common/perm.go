package common

import (
	"strings"

	"github.com/uagolang/guard/utils"
)

type Permission interface {
	IsAdmin() bool
	GetAction() string
	GetObject() string
	WithID(id string) *Perm
	GetObjectID() string
	GetMidSentenceDescription() string
	GetDeniedDescription() string
}

// Perm describes what can be done with an object.
// action could apply to a specific object or to all objects of a type.
// e.g. "create" applies to a type of object, as there is no id to specify yet,
// but "delete" could apply to a specific object - when id is specified, or to all objects of a type - when id is "*" (wildcard).
type Perm struct {
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

func (p *Perm) IsAdmin() bool {
	return p.Admin
}

func (p *Perm) GetAction() string {
	return p.Action.String()
}

func (p *Perm) GetObject() string {
	return p.Object.String()
}

// WithID specify a concrete object ID if the permission allows it.
func (p *Perm) WithID(id string) *Perm {
	if p.ObjectID == Wildcard && id != "" {
		p.ObjectID = id
	}

	return p
}

// GetObjectID get object ID if applicable and specified.
func (p *Perm) GetObjectID() string {
	if p.ObjectID == Wildcard || p.ObjectID == "" {
		return ""
	}

	return p.ObjectID
}

func (p *Perm) GetMidSentenceDescription() string {
	return strings.ToLower(p.Desc[:1]) + p.Desc[1:]
}

func (p *Perm) GetDeniedDescription() string {
	description := p.GetMidSentenceDescription()
	description = strings.ReplaceAll(description, " an ", " this ")
	description = strings.ReplaceAll(description, " a ", " this ")

	return description
}

func GetPerm(perms []Perm, obj, objID, action string) (Perm, error) {
	p, found := utils.Find(perms, func(perm Perm) bool {
		return perm.GetObject() == obj && perm.GetAction() == action
	})
	if !found {
		return Perm{}, ErrNotFoundPerm(obj, action)
	}

	return *(p.WithID(objID)), nil
}
