package main

import (
	"fmt"
	"log"
	"time"

	"github.com/RTS-Framework/Gleam-RT/runtime/watchdog"
)

func main() {
	err := watchdog.Enable()
	if err != nil {
		log.Fatal("failed to enable watchdog:", err)
	}

	go func() {
		for {
			fmt.Println("application is healthy")

			fmt.Println("kick watchdog")
			err := watchdog.Kick()
			if err != nil {
				log.Fatal("failed to kick watchdog:", err)
			}
			time.Sleep(time.Second)
		}
	}()

	time.Sleep(3 * time.Second)

	err = watchdog.Disable()
	if err != nil {
		log.Fatal("failed to disable watchdog:", err)
	}
}
