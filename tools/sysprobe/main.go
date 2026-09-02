package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/forgepanel/forgepanel/internal/sysinfo"
)

func main() {
	a := sysinfo.ReadNetwork()
	s := sysinfo.Read("/")
	time.Sleep(2 * time.Second)
	b := sysinfo.ReadNetwork()
	rx, tx := sysinfo.Rate(a, b, 2*time.Second)
	out, _ := json.MarshalIndent(s, "", " ")
	fmt.Println(string(out))
	fmt.Printf("rate over 2s: rx=%.0f B/s tx=%.0f B/s\n", rx, tx)
}
