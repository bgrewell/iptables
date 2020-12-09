package iptables

import (
	"fmt"
)

const (
	TargetBalanceStr string = "--to-destination"
)

type TargetBalance struct {
	StartingIpAddress string
	EndingIpAddress   string
}

func (t TargetBalance) String() string {
	return TargetJump{
		Value: fmt.Sprintf("BALANCE %s %s-%s", TargetBalanceStr, t.StartingIpAddress, t.EndingIpAddress),
	}.String()
}

func (t TargetBalance) Validate(rule Rule) error {
	return nil
}
