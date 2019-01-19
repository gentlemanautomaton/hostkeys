package hostkeys_test

import (
	"fmt"

	"github.com/gentlemanautomaton/hostkeys"
)

func ExampleScan() {
	keys, err := hostkeys.Scan("github.com")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Print(hostkeys.Marshal(keys...))
}
