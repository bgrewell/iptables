package iptables

// InvertableString is a helper type that wraps a string value with a flag that
// tells iptables if it should be inverted in the command
type InvertableString struct {
	Value    string `json:"value" yaml:"value" xml:"value"`
	Inverted bool   `json:"inverted" yaml:"inverted" xml:"inverted"`
}

// CounterValues is a helper type that wraps the packet and byte counters used when
// setting the counter values for a new rule
type CounterValues struct {
	Packets int `json:"packets" yaml:"packets" xml:"packets"`
	Bytes   int `json:"bytes" yaml:"bytes" xml:"bytes"`
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

// These constants are the valid valids that can be used to reprsent actions
const (
	ActionJump   Action = "jump"
	ActionGoTo   Action = "goto"
	ActionAccept Action = "ACCEPT"
	ActionDrop   Action = "DROP"
	ActionQueue  Action = "QUEUE"
	ActionReturn Action = "RETURN"
)
