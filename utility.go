package iptables

import (
	"fmt"
	. "github.com/BGrewell/go-execute"
	"log"
	"strings"
	"sync"
)

// TODO: There is a problem with how all of these methods implement their functionality. They use line numbers
//		 which can change if a rule is added/removed between the enumeration and the execution. This should be
//		 addressed at some point although for this use case it is a low probability event as we use locks which
//		 prevent race conditions in our code so it would have to happen by external modification which is less
//		 likely in our use cases.

// Utility functions for managing IPTables rules
var (
	tables = []string{"filter", "nat", "mangle", "raw"}
	errNoMatch = fmt.Errorf("no matching rule was found")
	tableLock = sync.Mutex{}
)

type RuleLocation struct {
	Table string
	Chain string
	Line string
}

func AddCustomTable(table string) {
	tables = append(tables, table)
}

func CommentExists(comment string) bool {
	tableLock.Lock()
	defer tableLock.Unlock()
	_, err := FindRuleByComment(comment)
	if err != nil && err == errNoMatch {
		return false
	}
	return true
}

func IdExists(id string) bool {
	tableLock.Lock()
	defer tableLock.Unlock()
	_, err := FindRuleById(id)
	if err != nil && err == errNoMatch {
		return false
	}
	return true
}

func NameExists(name string) bool {
	tableLock.Lock()
	defer tableLock.Unlock()
	_, err := FindRuleByName(name)
	if err != nil && err == errNoMatch {
		return false
	}
	return true
}

func AppExists(app string) bool {
	tableLock.Lock()
	defer tableLock.Unlock()
	_, err := FindRuleByApp(app)
	if err != nil && err == errNoMatch {
		return false
	}
	return true
}

func DeleteByComment(comment string) error {
	tableLock.Lock()
	defer tableLock.Unlock()
	location, err := FindRuleByComment(comment)
	if err != nil {
		return err
	}
	deleteCmd := fmt.Sprintf("iptables -t %s -D %s %s", location.Table, location.Chain, location.Line)
	_, err = ExecuteCmd(deleteCmd)
	if err != nil {
		return err
	}
	return nil
}

func DeleteById(id string) error {
	tableLock.Lock()
	defer tableLock.Unlock()
	location, err := FindRuleById(id)
	if err != nil {
		return err
	}
	deleteCmd := fmt.Sprintf("iptables -t %s -D %s %s", location.Table, location.Chain, location.Line)
	_, err = ExecuteCmd(deleteCmd)
	if err != nil {
		return err
	}
	return nil
}

func DeleteByName(name string) error {
	tableLock.Lock()
	defer tableLock.Unlock()
	location, err := FindRuleByName(name)
	if err != nil {
		return err
	}
	deleteCmd := fmt.Sprintf("iptables -t %s -D %s %s", location.Table, location.Chain, location.Line)
	_, err = ExecuteCmd(deleteCmd)
	if err != nil {
		return err
	}
	return nil
}

func DeleteByApp(app string) error {
	tableLock.Lock()
	defer tableLock.Unlock()
	location, err := FindRuleByApp(app)
	if err != nil {
		return err
	}
	deleteCmd := fmt.Sprintf("iptables -t %s -D %s %s", location.Table, location.Chain, location.Line)
	_, err = ExecuteCmd(deleteCmd)
	if err != nil {
		return err
	}
	return nil
}

func DeleteAllMatchingComments(comment string) error {
	tableLock.Lock()
	defer tableLock.Unlock()
	for {
		err := DeleteByComment(comment)
		if err != nil && err == errNoMatch {
			break
		} else if err != nil {
			return err
		}
	}

	return nil
}

func DeleteAllMatchingId(id string) error {
	tableLock.Lock()
	defer tableLock.Unlock()
	for {
		err := DeleteById(id)
		if err != nil && err == errNoMatch {
			break
		} else if err != nil {
			return err
		}
	}

	return nil
}

func DeleteAllMatchingName(name string) error {
	tableLock.Lock()
	defer tableLock.Unlock()
	for {
		err := DeleteByName(name)
		if err != nil && err == errNoMatch {
			break
		} else if err != nil {
			return err
		}
	}

	return nil
}

func DeleteAllMatchingApp(app string) error {
	tableLock.Lock()
	defer tableLock.Unlock()
	for {
		err := DeleteByApp(app)
		if err != nil && err == errNoMatch {
			break
		} else if err != nil {
			return err
		}
	}

	return nil
}

func FindRuleByComment(comment string) (location *RuleLocation, err error) {
	return FindRuleByCommentWithPrefix(comment, nil)
}

func FindRuleById(id string) (location *RuleLocation, err error) {
	prefix := "id"
	return FindRuleByCommentWithPrefix(id, &prefix)
}

func FindRuleByName(name string) (location *RuleLocation, err error) {
	prefix := "name"
	return FindRuleByCommentWithPrefix(name, &prefix)
}

func FindRuleByApp(app string) (location *RuleLocation, err error) {
	prefix := "app"
	return FindRuleByCommentWithPrefix(app, &prefix)
}

func FindRuleByCommentWithPrefix(comment string, prefix *string) (location *RuleLocation, err error) {
	for _, table := range tables {
		chains, err := EnumerateChains(table)
		if err != nil {
			return nil, err
		}
		for _, chain := range chains {
			rules, err := EnumerateRules(table, chain)
			if err != nil {
				return nil, err
			}

			for _, rule := range rules {
				mark := 0
				for mark < len(rule) {
					start := strings.Index(rule[mark:], "/* ")
					end := strings.Index(rule[mark:], " */")
					if start == -1 || end == -1 {
						break
					}

					// NOTE: there is a strange issue where comments quoted on the cmd line don't have comments in the
					// output but for some reason when it is done through this module they do have the double quotes on
					// the comment so we need to deal with them being there or not being there
					// trim off the markers and spaces
					c := rule[mark+start+3:mark+end]
					c = strings.ReplaceAll(c, "\"", "")

					match := comment
					if prefix == nil {
						// strip off app: | id: | name: prefix's
						c = strings.ReplaceAll(c, "app:", "")
						c = strings.ReplaceAll(c, "id:", "")
						c = strings.ReplaceAll(c, "name:", "")
					} else {
						match = fmt.Sprintf("%s:%s", *prefix, comment)
					}

					mark = mark+end+2
					if match == c {
						l := &RuleLocation{
							Table: table,
							Chain: chain,
							Line:  strings.Fields(rule)[0],
						}
						return l, nil
					}
				}

			}
		}
	}
	return nil, errNoMatch
}

func EnumerateRules(table string, chain string) (rules []string, err error) {
	listCmd := fmt.Sprintf("iptables -t %s -vnL %s --line-numbers", table, chain)
	result, err := ExecuteCmd(listCmd)
	if err != nil {
		return nil, err
	}
	rules = strings.Split(result, "\n")[2:]
	return rules, nil
}

func EnumerateChains(table string) (chains []string, err error) {
	chains = make([]string, 0)
	listCmd := fmt.Sprintf("iptables -t %s -vnL --line-numbers", table)
	result, err := ExecuteCmd(listCmd)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Chain ") {
			fields := strings.Fields(line)
			chains = append(chains, fields[1])
		}
	}
	return chains, nil
}

func EnumerateUsedTables() (tables []string, err error) {
	tables = make([]string, 0)
	cmd := "cat /proc/net/ip_tables_names"
	result, err := ExecuteCmd(cmd)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			tables = append(tables, line)
		}
	}
	return tables, nil
}

func ConvertIptablesLineToRule(table string, line string) (rule *Rule, err error) {
	rule = &Rule{
		Table: table,
	}
	fields := strings.Fields(line)
	inverted := false
	for idx := 0; idx < len(fields); {
		// Detect negation and increment the index
		if fields[idx] == "!" {
			inverted = true
			idx += 1
		}

		switch fields[idx] {
		case "-A", "-I":	// shouldn't ever be a -I but just in case
			rule.Chain = fields[idx+1]
			idx++
		case "-s":
			rule.Source = InvertableString{
				Value:    fields[idx+1],
				Inverted: inverted,
			}
			idx++
		case "-d":
			rule.Destination = InvertableString{
				Value:    fields[idx+1],
				Inverted: inverted,
			}
			idx++
		case "-p":
			rule.Protocol = InvertableString{
				Value:    fields[idx+1],
				Inverted: inverted,
			}
			idx++
		case "-m":
			rule.Match = InvertableString{
				Value:    fields[idx+1],
				Inverted: inverted,
			}
			idx++
		case "--sport", "--sports":
			rule.SourcePort = InvertableString{
				Value:    fields[idx+1],
				Inverted: inverted,
			}
			idx++
		case "--dport", "--dports":
			rule.DestinationPort = InvertableString{
				Value:    fields[idx+1],
				Inverted: inverted,
			}
			idx++

		default:
			log.Printf("warning: %s not a known field for iptables import\n", fields[idx])
			idx++
		}

		// Reset inverted
		inverted = false
	}
	return rule, nil
}

// 1: List/Enumerate all tables?? Just assume that nat/mangle/filter/raw are the only ones?
// 2: Get all rules in a consumable format -S?
// What do we need to know?
// 	- table
//	- chain
//  - parameters

//	0: pkts
//	1: bytes
//	2: target
//	3: protocol
//	4: options
//	5: input interface
//	6: output interface
//	7: source address
//	8: destination address
//	9: extra stuff

// Use -S option to get a more verbose output for the rules? We don't get packet counts so we would need to figure out
// how to get those in addition