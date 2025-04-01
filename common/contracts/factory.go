package contracts

type Factory interface {
	Scope(data ...string) Scope
	SubjectUser(id string) Subject
	SubjectRole(tenantID, id string) Subject
	SubjectGroup(tenantID, id string) Subject
	Object(s Scope, p any) Object
	GroupPolicy(sub, role Subject) GroupPolicy
	PolicyFromCasbin(p []string) (Policy, error)
	RolePolicyFromCasbin(p []string) (RolePolicy, error)
	GroupPolicyFromCasbin(p []string) (GroupPolicy, error)
}
