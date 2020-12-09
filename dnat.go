package iptables

import (
	"fmt"
	"strings"
)

const (
	TargetDNatStr string = "--to-destination"
)

type TargetDNat struct {
	DestinationIp        string
	DestinationIpRange   string
	DestinationPort      string
	DestinationPortRange string
}

func (t TargetDNat) String() string {
	parts := make([]string, 0)
	parts = append(parts, "DNAT")
	parts = append(parts, TargetDNatStr)
	if t.DestinationIpRange != "" {
		parts = append(parts, t.DestinationIpRange)
	} else {
		parts = append(parts, t.DestinationIp)
	}
	if t.DestinationPortRange != "" {
		parts = append(parts, fmt.Sprintf(":%s", t.DestinationPortRange))
	} else if t.DestinationPort != "" {
		parts = append(parts, fmt.Sprintf(":%s", t.DestinationPort))
	}

	return TargetJump{
		Value: strings.Join(parts, " "),
	}.String()
}

// Returns if the target is valid when applied with the specified rule
func (t TargetDNat) Validate(rule Rule) error {
	// Only valid on the mangle table
	if rule.Table != TableNat {
		return fmt.Errorf("target DNAT is only valid on the 'nat' table")
	}
	if rule.Chain != ChainOutput && rule.Chain != ChainPreRouting {
		return fmt.Errorf("target DNAT is only valid on the 'OUTPUT' or 'PREROUTING' chains")
	}
	if t.DestinationPort != "" && t.DestinationPortRange != "" && rule.Protocol.Value == "" {
		return fmt.Errorf("target DNAT destination port(s) are only valid when a protocol is specified on the rule")
	}
	return nil
}
