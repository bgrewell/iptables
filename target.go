package iptables

// ITarget is an interface for the target extensions
type ITarget interface {
	String() string
	Validate(rule Rule) error
}
