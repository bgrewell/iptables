package main

import (
	"fmt"
	"github.com/BGrewell/iptables"
)

func main() {

	tables, err := iptables.EnumerateUsedTables()
	if err != nil {
		fmt.Printf("error: %v\n", err)
	}
	for idx, table := range tables {
		fmt.Printf("%d: %s\n", idx, table)
	}

	limit := 10
	for idx := 0; idx < limit; {
		fmt.Printf("%d\n", idx)
		idx += 3
	}

}
