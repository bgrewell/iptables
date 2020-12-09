package iptables

import (
	"fmt"
)

const (
	TargetJumpStr string = "--jump"
)

type TargetJump struct {
	Value string
}

func (t TargetJump) String() string {
	return fmt.Sprintf("%s %s", TargetJumpStr, t.Value)
}

// Returns if the target is valid when applied with the specified rule
func (t TargetJump) Validate(rule Rule) error {
	return nil
}
