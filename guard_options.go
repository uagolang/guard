package guard

import (
	"github.com/casbin/casbin/v2"

	"github.com/uagolang/guard/common"
	"github.com/uagolang/guard/common/contracts"
)

type Option func(g *Guard)

func WithFactory(factory contracts.Factory) Option {
	return func(g *Guard) {
		g.factory = factory
	}
}

func WithEnforcer(enforcer *casbin.Enforcer) Option {
	return func(g *Guard) {
		g.casbin = enforcer
	}
}

func WithActions(actions []common.Action) Option {
	return func(g *Guard) {
		g.actions = actions
	}
}

func WithEntityObjects(entityObjects []common.EntityObject) Option {
	return func(g *Guard) {
		g.entityObjects = entityObjects
	}
}

func WithPerms(perms []common.Perm) Option {
	return func(g *Guard) {
		g.perms = perms
	}
}

func WithScopedObjects(scopedObjects map[contracts.ScopeLevel][]common.EntityObject) Option {
	return func(g *Guard) {
		g.scopedObjects = scopedObjects
	}
}
