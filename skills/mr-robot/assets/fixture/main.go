// INTENTIONALLY WEAK — demo target for gosec.
// Run: go run main.go "echo demo"
package main

import (
	"crypto/md5" //nolint:gosec // demo: G505 blocklisted import on purpose
	"fmt"
	"os"
	"os/exec"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: demo <shell command>")
		os.Exit(1)
	}
	// BUG (demo): G204 — subprocess launched with variable input
	out, _ := exec.Command("sh", "-c", os.Args[1]).CombinedOutput()
	fmt.Println(string(out))
	// BUG (demo): G505 — MD5 used for a "checksum"
	fmt.Printf("checksum: %x\n", md5.Sum([]byte(os.Args[1])))
}
