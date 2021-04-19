package iptables

import (
	"fmt"
)

const (
	TargetDSCPStr      string = "--set-dscp"
	TargetDSCPClassStr string = "--set-dscp-class"
)

type TargetDSCP struct {
	Value int `json:"value" yaml:"value" xml:"value"`
}

func (t TargetDSCP) String() string {
	return TargetJump{
		Value: fmt.Sprintf("DSCP %s %d", TargetDSCPStr, t.Value),
	}.String()
}

// Returns if the target is valid when applied with the specified rule
func (t TargetDSCP) Validate(rule Rule) error {
	// Only valid on the mangle table
	if rule.Table != TableMangle {
		return fmt.Errorf("target DSCP is only valid on the 'mangle' table")
	}
	return nil
}

type TargetDSCPClass struct {
	Class string `json:"class" yaml:"class" xml:"class"`
}

func (t TargetDSCPClass) String() string {
	return TargetJump{
		Value: fmt.Sprintf("DSCP %s %d", TargetDSCPClassStr, t.Class),
	}.String()
}

// Returns if the target is valid when applied with the specified rule
func (t TargetDSCPClass) Valid(rule Rule) bool {
	// Only valid on the mangle table
	return rule.Table == TableMangle
}
