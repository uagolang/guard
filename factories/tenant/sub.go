package tenant

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/uagolang/guard/common"
	"github.com/uagolang/guard/common/contracts"
)

type subjectKind int

const (
	subjectKindRole = subjectKind(iota + 1)
	subjectKindUser
	subjectKindGroup
)

// subject for the casbin model
//
// Possible kinds:
//
// Role: 1/tenantID/roleID
//
// User: 2/tenantID/userID
//
// Group: 3/tenantID/groupID
type subject struct {
	Kind     subjectKind `json:"kind"`
	TenantID string      `json:"org_id"`
	ID       string      `json:"id"`
}

func (s *subject) ToCasbin() string {
	if s.TenantID == "" {
		panic(fmt.Sprintf("subject tenantID is empty: %v", s))
	}
	if s.ID == "" {
		panic(fmt.Sprintf("subject id is empty: %v", s))
	}

	return fmt.Sprintf("%d/%s/%s", s.Kind, s.TenantID, s.ID)
}

func (s *subject) IsRole() bool {
	return s.Kind == subjectKindRole
}

func (s *subject) IsUser() bool {
	return s.Kind == subjectKindUser
}

func (s *subject) IsGroup() bool {
	return s.Kind == subjectKindGroup
}

func newSubjectUser(id string) contracts.Subject {
	return &subject{
		Kind:     subjectKindUser,
		TenantID: "_",
		ID:       id,
	}
}

func newSubjectRole(tenantID, id string) contracts.Subject {
	return &subject{
		Kind:     subjectKindRole,
		TenantID: tenantID,
		ID:       id,
	}
}

func newSubjectGroup(tenantID, id string) contracts.Subject {
	return &subject{
		Kind:     subjectKindGroup,
		TenantID: tenantID,
		ID:       id,
	}
}

func newSubjectFromCasbin(s string) (contracts.Subject, error) {
	sp := strings.Split(s, "/")
	if len(sp) != 3 {
		return nil, common.ErrUnknownType("subject", s)
	}
	kind, err := strconv.Atoi(sp[0])
	if err != nil {
		return nil, common.ErrUnknownType("subject kind", sp[0])
	}

	return &subject{
		Kind:     subjectKind(kind),
		TenantID: sp[1],
		ID:       sp[2],
	}, nil
}
