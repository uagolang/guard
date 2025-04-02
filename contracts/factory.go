package contracts

type Factory interface {
	Scope(data ScopeData) Scope
	SubjectUser(id string) Subject
	SubjectRole(tenantID, id string) Subject
	SubjectGroup(tenantID, id string) Subject
	Object(s Scope, p Perm) Object
	GroupPolicy(sub, role Subject) GroupPolicy
	PolicyFromCasbin(p []string) (Policy, error)
	RolePolicyFromCasbin(p []string) (RolePolicy, error)
	RolePoliciesFromCasbin(p [][]string) ([]RolePolicy, error)
	GroupPolicyFromCasbin(p []string) (GroupPolicy, error)
}
