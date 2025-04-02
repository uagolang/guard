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
	SetPerm(p Perm) Object
	GetPerm(list []Perm, action string) (Perm, error)
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
	Perm() Perm
	Effect() string
}

type RolePolicy interface {
	SetScope(s Scope) RolePolicy
	Scope() Scope
	SetPerm(p Perm) RolePolicy
	Perm() Perm
	Effect() string
	ToCasbin(sub Subject) []string
}

type GroupPolicy interface {
	ToCasbin() []string
}

type PolicyEffect string

func (e PolicyEffect) String() string {
	return string(e)
}

const (
	PolicyEffectAllow PolicyEffect = "allow"
	PolicyEffectDeny  PolicyEffect = "deny"
)

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
