package main

import (
	"bufio"
	"fmt"
	iptables "github.com/BGrewell/iptables/pkg"
	"os"
)

func main() {

	// Test rule
	r := iptables.Rule{
		Table: iptables.TableNat,
		Chain: iptables.ChainOutput,
		Target: iptables.TargetDNat{
			DestinationIp: "10.0.0.1",
		},
		Protocol: iptables.InvertableString{
			Value:    "tcp",
			Inverted: false,
		},
		Source: iptables.InvertableString{
			Value:    "1.2.3.4",
			Inverted: true,
		},
		Destination: iptables.InvertableString{
			Value:    "192.168.0.0/24",
			Inverted: false,
		},
		Debug: true,
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Adding rule")
	err := r.Append()
	if err != nil {
		fmt.Printf("failed to execute append: %s\n", err)
	}
	fmt.Printf("Rule added at line %d\n", r.RuleNumber)
	fmt.Println("Press enter to delete")
	reader.ReadString('\n')

	fmt.Println("Deleting rule")
	err = r.Delete()
	if err != nil {
		fmt.Printf("failed to execute delete: %s\n", err)
	}
	fmt.Println("Press enter to insert")
	reader.ReadString('\n')

	fmt.Println("Inserting rule")
	err = r.Insert(1)
	if err != nil {
		fmt.Printf("failed to execute intert: %s\n", err)
	}
	fmt.Println("Press enter to change the destination")
	reader.ReadString('\n')

	r.Destination = iptables.InvertableString{
		Value:    "192.168.100.0/24",
		Inverted: false,
	}

	fmt.Println("Replacing rule")
	err = r.Replace()
	if err != nil {
		fmt.Printf("failed to execute replace: %s\n", err)
	}
	fmt.Println("Press enter to delete rule")
	reader.ReadString('\n')

	fmt.Println("Deleting rule")
	err = r.Delete()
	if err != nil {
		fmt.Printf("failed to execute delete: %s\n", err)
	}
	fmt.Println("Done!")
}
