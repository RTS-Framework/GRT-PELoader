package main

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/RTS-Framework/Gleam-RT/runtime"
)

func main() {
	data := strings.Repeat("secret", 1)

	for i := 0; i < 3; i++ {
		err := gleamrt.Sleep(time.Second)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("sleep complete")
	}

	fmt.Println(data)
}
