// main.go demonstrates the basic usage of the CEF parser with JSON output..
package main

import (
	"fmt"
	"log"

	"github.com/ren3gadem4rm0t/cef-parser-go/parser"
)

func main() {

	event := parser.ImpervaCEF5

	cefEvent, err := parser.ParseCEF(event)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(cefEvent.AsJSON())

	// Return the CEF object to the pool when done
	parser.Release(cefEvent)
}
