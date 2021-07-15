package iptables

import (
	"fmt"
	. "github.com/BGrewell/go-execute"
	"strconv"
	"strings"
)

// Rule represents a rule which can be added to or removed from iptables.
type Rule struct {
	Id              string           `json:"id,omitempty" yaml:"id" xml:"id"`
	Name            string           `json:"name,omitempty" yaml:"name" xml:"name"`
	App             string           `json:"-" yaml:"-" xml:"-"`
	Table           string           `json:"table,omitempty" yaml:"table" xml:"table"`
	Chain           string           `json:"chain,omitempty" yaml:"chain" xml:"chain"`
	Target          ITarget          `json:"target,omitempty" yaml:"target" xml:"target"`
	Command         Cmd              `json:"command,omitempty" yaml:"command" xml:"command"`
	Protocol        InvertableString `json:"protocol,omitempty" yaml:"protocol" xml:"protocol"`
	Source          InvertableString `json:"source,omitempty" yaml:"source" xml:"source"`
	Destination     InvertableString `json:"destination,omitempty" yaml:"destination" xml:"destination"`
	SourcePort      InvertableString `json:"source_port,omitempty" yaml:"source_port" xml:"source_port"`
	DestinationPort InvertableString `json:"destination_port,omitempty" yaml:"destination_port" xml:"destination_port"`
	InputInterface  InvertableString `json:"input_interface,omitempty" yaml:"input_interface" xml:"input_interface"`
	OutputInterface InvertableString `json:"output_interface,omitempty" yaml:"output_interface" xml:"output_interface"`
	Counters        CounterValues    `json:"counters,omitempty" yaml:"counters" xml:"counters"`
	ViewOnly        bool             `json:"view_only,omitempty" yaml:"view_only" xml:"view_only"`
	RuleNumber      int              `json:"rule_number,omitempty" yaml:"rule_number" xml:"rule_number"`
	Debug           bool             `json:"debug,omitempty" yaml:"debug" xml:"debug"`
	Valid           bool             `json:"valid,omitempty" yaml:"valid" xml:"valid"`
	Applied         bool             `json:"applied,omitempty" yaml:"applied" xml:"applied"`
	IpVersion       IPVer            `json:"ip_version,omitempty" yaml:"ip_version" xml:"ip_version"`
}

// Append adds a new rule to the specified chain at the end
func (r *Rule) Append() (err error) {
	if validation := r.Validate(); validation != nil {
		return validation
	}
	r.Command = CmdAppend
	err = r.executeRule()
	if err != nil {
		r.setState(false, false)
		return err
	}
	r.setState(true, true)
	r.RuleNumber, err = GetRuleIndex(r.Table, r.Chain, r.IpVersion)
	if err != nil {
		r.setState(false, true)
	}
	return nil
}

// Insert adds a new rule to the specified chain at the index passed
func (r *Rule) Insert(index int) (err error) {
	if validation := r.Validate(); validation != nil {
		return validation
	}
	r.Command = CmdInsert
	r.RuleNumber = index
	err = r.executeRule()
	if err != nil {
		r.setState(false, false)
		return err
	}
	r.setState(true, true)
	return nil
}

// Replace replaces a rule in the specified chain
func (r *Rule) Replace() (err error) {
	if validation := r.Validate(); validation != nil {
		return validation
	}
	r.Command = CmdReplace
	err = r.executeRule()
	if err != nil {
		r.setState(false, r.Applied)
		return err
	}
	r.setState(true, true)
	return nil
}

// Delete removes a rule from the specified chain
func (r *Rule) Delete() (err error) {
	if r.Id != "" {
		// if the rule has an id just use that to delete
		err = DeleteByComment(r.Id)
		if err != nil {
			r.setState(false, r.Applied)
			return err
		}
		r.setState(true, false)
		return nil
	}
	if validation := r.Validate(); validation != nil {
		return validation
	}
	r.Command = CmdDelete
	err = r.executeRule()
	if err != nil {
		r.setState(false, r.Applied)
		return err
	}
	r.setState(true, false)
	return nil
}

func (r *Rule) String() string {
	r.setDefaults()
	var output = make([]string, 0)
	binaryPath, err := GetIptablesBinaryPath(r.IpVersion)
	if err != nil {
		panic(err)
	}
	output = append(output, binaryPath)

	if r.Table != "" {
		output = append(output, fmt.Sprintf("-t %s", r.Table))
	}

	if r.Command != "" {
		output = append(output, fmt.Sprintf("--%s", r.Command))

		if r.Chain != "" {
			output = append(output, r.Chain)

			if r.Command == CmdInsert || r.Command == CmdReplace {
				output = append(output, strconv.Itoa(r.RuleNumber))
			}
		}
	}

	if r.Protocol.Value != "" {
		invertChar := GetInvertPattern(r.Protocol.Inverted)
		output = append(output, fmt.Sprintf("%s--protocol %s", invertChar, r.Protocol.Value))
	}

	if r.Source.Value != "" {
		invertChar := GetInvertPattern(r.Source.Inverted)
		output = append(output, fmt.Sprintf("%s--source %s", invertChar, r.Source.Value))
	}

	if r.Destination.Value != "" {
		invertChar := GetInvertPattern(r.Destination.Inverted)
		output = append(output, fmt.Sprintf("%s--destination %s", invertChar, r.Destination.Value))
	}

	if r.SourcePort.Value != "" {
		invertChar := GetInvertPattern(r.SourcePort.Inverted)
		output = append(output, fmt.Sprintf("--match multiport %s--sports %s", invertChar, r.SourcePort.Value))
	}

	if r.DestinationPort.Value != "" {
		invertChar := GetInvertPattern(r.DestinationPort.Inverted)
		output = append(output, fmt.Sprintf("--match multiport %s--dports %s", invertChar, r.DestinationPort.Value))
	}

	if r.InputInterface.Value != "" {
		invertChar := GetInvertPattern(r.InputInterface.Inverted)
		output = append(output, fmt.Sprintf("%s--in-interface %s", invertChar, r.InputInterface.Value))
	}

	if r.OutputInterface.Value != "" {
		invertChar := GetInvertPattern(r.OutputInterface.Inverted)
		output = append(output, fmt.Sprintf("%s--out-interface %s", invertChar, r.OutputInterface.Value))
	}

	if r.Target != nil {
		output = append(output, r.Target.String())
	}

	if r.Id != "" {
		output = append(output, fmt.Sprintf("-m comment --comment \"id:%s\"", r.Id))
	}

	if r.Name != "" {
		output = append(output, fmt.Sprintf("-m comment --comment \"name:%s\"", r.Name))
	}

	if r.App != "" {
		output = append(output, fmt.Sprintf("-m comment --comment \"app:%s\"", r.App))
	}

	return strings.Join(output, " ")
}

func (r *Rule) Validate() (err error) {
	//TODO: Add all the validity checks here
	if err := r.Target.Validate(*r); err != nil {
		return err
	}
	return nil
}

func (r *Rule) executeRule() error {
	if r.ViewOnly {
		fmt.Println(r.String())
		return nil
	}
	result, err := ExecuteCmd(r.String())
	if r.Debug == true {
		fmt.Println(result)
	}
	return err
}

func (r *Rule) setDefaults() {
	if r.IpVersion == "" {
		r.IpVersion = IPv4
	}

	if r.Target == nil {
		r.Target = TargetJump{
			Value: TargetAccept,
		}
	}

	if r.Command == "" {
		r.Command = CmdAppend
	}
}

func (r *Rule) setState(valid, applied bool) {
	r.Valid = valid
	r.Applied = applied
}
