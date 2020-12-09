package iptables

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// InvertableString is a helper type that wraps a string value with a flag that
// tells iptables if it should be inverted in the command
type InvertableString struct {
	Value    string `json:"value,omitempty" yaml:"value" xml:"value"`
	Inverted bool   `json:"inverted,omitempty" yaml:"inverted" xml:"inverted"`
}

// CounterValues is a helper type that wraps the packet and byte counters used when
// setting the counter values for a new rule
type CounterValues struct {
	Packets int `json:"packets,omitempty" yaml:"packets" xml:"packets"`
	Bytes   int `json:"bytes,omitempty" yaml:"bytes" xml:"bytes"`
}

// Cmd represents the commands that are supported by iptables
type Cmd string

// These constants are the valid values that can be used to represent commands
const (
	CmdAppend      Cmd = "append"
	CmdDelete      Cmd = "delete"
	CmdInsert      Cmd = "insert"
	CmdReplace     Cmd = "replace"
	CmdList        Cmd = "list"
	CmdFlush       Cmd = "flush"
	CmdZero        Cmd = "zero"
	CmdNewChain    Cmd = "new-chain"
	CmdDeleteChain Cmd = "delete-chain"
	CmdPolicy      Cmd = "policy"
	CmdRenameChain Cmd = "rename-chain"
)

// Action is a type that represents the valid actions for a rule to take
type Action string

// These constants are the valid values that can be used to represent actions
const (
	ActionJump Action = "jump"
	ActionGoTo Action = "goto"
)

// Target represents the commonly used targets
type Target string

// These constants are commonly used targets
const (
	TargetAccept string = "ACCEPT"
	TargetDrop   string = "DROP"
	TargetQueue  string = "QUEUE"
	TargetReturn string = "RETURN"
)

// IPVer is a type that represents the IP protocol version
type IPVer string

const (
	IPv6 IPVer = "ipv6"
	IPv4 IPVer = "ipv4"
)

// Chain represents the commonly used chains
type Chain string

// These constants are commonly used chains
const (
	ChainInput       string = "INPUT"
	ChainOutput      string = "OUTPUT"
	ChainForward     string = "FORWARD"
	ChainPreRouting  string = "PREROUTING"
	ChainPostRouting string = "POSTROUTING"
)

// Table represents the default tables
type Table string

// These constants are the default tables
const (
	TableRaw      string = "raw"
	TableFilter   string = "filter"
	TableNat      string = "nat"
	TableMangle   string = "mangle"
	TableSecurity string = "security"
)

func GetIptablesBinaryPath(ipVer IPVer) (cmd string, err error) {
	var binaryName string
	if ipVer == IPv6 {
		binaryName = "ip6tables"
	} else {
		binaryName = "iptables"
	}

	path, err := exec.LookPath(binaryName)
	if err != nil {
		return "", err
	}

	return path, nil
}

func GetInvertPattern(inverted bool) string {
	if inverted {
		return "! "
	}
	return ""
}


func GetRuleIndex(table string, chain string, ipVer IPVer) (ruleNum int, err error) {
	// note: the only rule that we should need to figure out the rule number for is the append, an insert we are
	// going to be in control of passing the index to insert it at. For an append we are going to naively assume that
	// the rule index is the index of the last rule in the chain. We protect against no rules being in the chain here
	// but we don't protect against a race condition. This only has a potential for problems with other replaces as it
	// would replace the wrong rule. Deletes are not affected as they are done by specification not by number.
	// iptables -t nat --list INPUT --line-numbers --verbose | sed -n '$p' | awk '{print $1}'
	iptables, err := GetIptablesBinaryPath(ipVer)
	if err != nil {
		return -1, err
	}
	cmd := fmt.Sprintf("%s -t %s --list %s --line-numbers", iptables, table, chain)
	results, err := ExecuteCmd(cmd)
	if err != nil {
		return -1, err
	}
	results = strings.TrimSpace(results)

	lines := strings.Split(results, "\n")
	fields := strings.Fields(lines[len(lines)-1])

	result := strings.TrimSpace(fields[0])
	value, err := strconv.ParseInt(result, 10, 64)
	if err != nil {
		return -1, err
	}
	return int(value), nil
}