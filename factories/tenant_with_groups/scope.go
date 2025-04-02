package tenant_with_groups

import (
	"github.com/uagolang/guard/common"
	"github.com/uagolang/guard/contracts"
)

const (
	ScopeDataTenantIDName = "tenant_id"
)

type ScopeOption func(s *Scope)

func WithSystemName(name string) ScopeOption {
	return func(s *Scope) {
		s.SystemName = name
	}
}

func WithTenantName(name string) ScopeOption {
	return func(s *Scope) {
		s.TenantName = name
	}
}

func WithData(data contracts.ScopeData) ScopeOption {
	return func(s *Scope) {
		s.Data = data
	}
}

func newScope(opts ...ScopeOption) contracts.Scope {
	s := &Scope{
		SystemName: "System",
		TenantName: "Tenant",
		Data:       contracts.ScopeData{},
	}
	for _, opt := range opts {
		opt(s)
	}

	return s
}

type Scope struct {
	TenantName string
	SystemName string
	Data       contracts.ScopeData
}

func (s *Scope) Name() string {
	switch s.Level() {
	case contracts.ScopeLevelTenant:
		return s.TenantName
	default:
		return s.SystemName
	}
}

func (s *Scope) Level() contracts.ScopeLevel {
	if s.Data[ScopeDataTenantIDName] != common.Wildcard {
		return contracts.ScopeLevelTenant
	}

	return contracts.ScopeLevelSystem
}

func (s *Scope) Contains(other contracts.Scope) bool {
	tenantScope, ok := other.(*Scope)
	if !ok {
		return false
	}

	return scopeContains(s.Data[ScopeDataTenantIDName], tenantScope.Get(ScopeDataTenantIDName))
}

func (s *Scope) Get(key string) string {
	return s.Data.Get(key)
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
