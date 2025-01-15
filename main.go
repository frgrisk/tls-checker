package main

import (
	"log"

	"github.com/frgrisk/tls-checker/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
