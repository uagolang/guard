package contracts

type Enum interface {
	List() any
	Strings() []string
	Validate() error
}
