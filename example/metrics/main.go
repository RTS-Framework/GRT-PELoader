package main

import (
	"log"

	"github.com/davecgh/go-spew/spew"

	"github.com/RTS-Framework/Gleam-RT/runtime"
)

func main() {
	metrics, err := gleamrt.GetMetrics()
	if err != nil {
		log.Fatal(err)
	}
	spew.Dump(metrics)
}
