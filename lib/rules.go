package iptables

import "fmt"

// Rule represents a rule which can be added to or removed from iptables.
type Rule struct {
	Table           string           `json:"table" yaml:"table" xml:"table"`
	Chain           string           `json:"chain" yaml:"chain" xml:"chain"`
	Target          string           `json:"target" yaml:"target" xml:"target"`
	TargetAction    Action           `json:"target_action" yaml:"target_action" xml:"target_action"`
	Command         Cmd              `json:"command" yaml:"command" xml:"command"`
	Protocol        InvertableString `json:"protocol" yaml:"protocol" xml:"protocol"`
	Source          InvertableString `json:"source" yaml:"source" xml:"source"`
	Destination     InvertableString `json:"destination" yaml:"destination" xml:"destination"`
	InputInterface  InvertableString `json:"input_interface" yaml:"input_interface" xml:"input_interface"`
	OutputInterface InvertableString `json:"output_interface" yaml:"output_interface" xml:"output_interface"`
	Counters        CounterValues    `json:"counters" yaml:"counters" xml:"counters"`
}

// Append adds a new rule to the specified chain at the end
func (r *Rule) Append() (err error) {
	return fmt.Errorf("not implmented")
}

// Insert adds a new rule to the specified chain at the index passed
func (r *Rule) Insert(index int) (err error) {
	return fmt.Errorf("not implemented")
}

// Replace replaces a rule in the specified chain
func (r *Rule) Replace() (err error) {
	return fmt.Errorf("not implemented")
}

// Delete removes a rule from the specified chain
func (r *Rule) Delete() (err error) {
	return fmt.Errorf("not implemented")
}
