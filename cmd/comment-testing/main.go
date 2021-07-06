package main

import (
	"fmt"
	"github.com/BGrewell/iptables"
)

func main() {

	//rule := iptables.Rule{
	//	Id:              "test:12345",
	//	Table:           iptables.TableFilter,
	//	Chain:           iptables.ChainForward,
	//	Target:          iptables.TargetJump{
	//		Value: iptables.TargetAccept,
	//	},
	//	Protocol:        iptables.InvertableString{
	//		Value: "tcp",
	//		Inverted: false,
	//	},
	//	Source:          iptables.InvertableString{
	//		Value: "1.2.3.4",
	//		Inverted: false,
	//	},
	//}
	//
	//rule.Debug = true
	//err := rule.Append()
	//if err != nil {
	//	fmt.Printf("failed to add rule: %s\n", err)
	//	return
	//}
	//fmt.Println("added rule")
	//
	//time.Sleep(10 * time.Second)

	//err := iptables.DeleteByComment("test")
	//if err != nil {
	//	fmt.Printf("failed to delete by id: %s\n", err)
	//	return
	//}
	//fmt.Println("deleted rule")

	err := iptables.DeleteAllMatching("testing")
	if err != nil {
		fmt.Printf("error: %v\n", err)
	}
}
