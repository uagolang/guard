package contracts

type Perm interface {
	IsAdmin() bool
	GetAction() string
	GetObject() string
	WithID(id string) Perm
	GetObjectID() string
	GetMidSentenceDescription() string
	GetDeniedDescription() string
}
