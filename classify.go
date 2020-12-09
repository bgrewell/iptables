package iptables

import (
	"fmt"
)

const (
	TargetClassifyStr string = "--set-class"
)

type TargetClassify struct {
	Major int
	Minor int
}

func (t TargetClassify) String() string {
	return TargetJump{
		Value: fmt.Sprintf("CLASSIFY %s %d:%d", TargetClassifyStr, t.Major, t.Minor),
	}.String()
}

func (t TargetClassify) Validate(rule Rule) error {
	return nil
}
