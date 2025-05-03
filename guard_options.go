package guard

import (
	"github.com/uagolang/guard/common"
	"github.com/uagolang/guard/contracts"
)

type Option func(g *Guard)

func WithActions(actions ...common.Action) Option {
	return func(g *Guard) {
		g.actions = append(g.actions, actions...)
	}
}

func WithEntityObjects(entityObjects ...common.EntityObject) Option {
	return func(g *Guard) {
		g.entityObjects = append(g.entityObjects, entityObjects...)
	}
}

func WithPerms(perms ...contracts.Perm) Option {
	return func(g *Guard) {
		g.perms = append(g.perms, perms...)
	}
}

func WithScopedObjects(scopedObjects map[contracts.ScopeLevel][]common.EntityObject) Option {
	return func(g *Guard) {
		g.scopedObjects = scopedObjects
	}
}
