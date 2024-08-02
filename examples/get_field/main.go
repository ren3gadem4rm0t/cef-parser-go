// main.go demonstrates the basic usage of the CEF parser with named field access.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/ren3gadem4rm0t/cef-parser-go/parser"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	event := parser.ImpervaCEF1

	cefEvent, err := parser.ParseCEFWithContext(ctx, event)
	if err != nil {
		log.Fatal(err)
	}

	cs10, err := cefEvent.Extensions.GetField("CS10")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("CS10: %+v\n", cs10)
}
