package pkg

import (
	"fmt"
)

const (
	TargetGotoStr string = "--goto"
)

type TargetGoto struct {
	Value string
}

func (t TargetGoto) String() string {
	return fmt.Sprintf("%s %s", TargetGotoStr, t.Value)
}

// Returns if the target is valid when applied with the specified rule
func (t TargetGoto) Validate(rule Rule) error {
	return nil
}
