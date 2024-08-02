// main.go demonstrates the basic usage of the CEF parser with field enumeration.
package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/ren3gadem4rm0t/cef-parser-go/parser"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	events := []string{parser.ImpervaCEF1, parser.CentrifyCEF}

	fmt.Println("-----")

	for _, event := range events {
		cefEvent, err := parser.ParseCEFWithContext(ctx, event)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("Vendor: %s\nProduct: %s\n", cefEvent.DeviceVendor, cefEvent.DeviceProduct)
		fmt.Printf("Extensions: %s\n", strings.Join(cefEvent.Extensions.GetFieldNames(), ", "))
		fmt.Println("-----")
	}
}
