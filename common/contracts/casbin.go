package contracts

type Subject interface {
	ToCasbin() string
	IsUser() bool
	IsRole() bool
	IsGroup() bool
}

type Object interface {
	ToCasbin() string
	SetScope(s Scope) Object
	GetScope() Scope
	SetPerm(p any) Object
	GetPerm(list any, obj, objID, action string) (any, error)
}

type Scope interface {
	Name() string
	Level() ScopeLevel
	Contains(other Scope) bool
	Get(v string) string
}

type Policy interface {
	Sub() Subject
	Scope() Scope
	Perm() any
	Effect() string
}

type RolePolicy interface {
	Scope() Scope
	Perm() any
	Effect() string
	ToCasbin(sub Subject) []string
}

type GroupPolicy interface {
	ToCasbin() []string
}

type ScopeData map[string]string

func (data ScopeData) Get(v string) string {
	return data[v]
}

type ScopeLevel int

func (sl ScopeLevel) Int() int {
	return int(sl)
}

const (
	ScopeLevelSystem ScopeLevel = iota
	ScopeLevelTenant
)
