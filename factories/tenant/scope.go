package tenant

import (
	"github.com/uagolang/guard/common"
	"github.com/uagolang/guard/common/contracts"
)

const (
	ScopeDataTenantIDName = "tenant_id"
)

type ScopeOption func(s *scope)

func WithSystemName(name string) ScopeOption {
	return func(s *scope) {
		s.systemName = name
	}
}

func WithTenantName(name string) ScopeOption {
	return func(s *scope) {
		s.tenantName = name
	}
}

func WithData(data map[string]string) ScopeOption {
	return func(s *scope) {
		s.data = data
	}
}

func newScope(opts ...ScopeOption) contracts.Scope {
	s := &scope{
		systemName: "System",
		tenantName: "Tenant",
		data:       map[string]string{},
	}
	for _, opt := range opts {
		opt(s)
	}

	return s
}

type scope struct {
	tenantName string
	systemName string
	data       contracts.ScopeData
}

func (s *scope) Name() string {
	switch s.Level() {
	case contracts.ScopeLevelTenant:
		return s.tenantName
	default:
		return s.systemName
	}
}

func (s *scope) Level() contracts.ScopeLevel {
	if s.data[ScopeDataTenantIDName] != common.Wildcard {
		return contracts.ScopeLevelTenant
	}

	return contracts.ScopeLevelSystem
}

func (s *scope) Contains(other contracts.Scope) bool {
	tenantScope, ok := other.(*scope)
	if !ok {
		return false
	}

	return scopeContains(s.data[ScopeDataTenantIDName], tenantScope.Get(ScopeDataTenantIDName))
}

func (s *scope) Get(key string) string {
	return s.data.Get(key)
}

func scopeContains(current, other string) bool {
	if current == "" {
		current = common.Wildcard
	}
	if other == "" {
		other = common.Wildcard
	}

	if current == common.Wildcard {
		return true
	}
	if current == other {
		return true
	}

	return false
}
