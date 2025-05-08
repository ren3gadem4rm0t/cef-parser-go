package main

import (
	"fmt"
	"runtime"
	"time"

	"github.com/ren3gadem4rm0t/cef-parser-go/parser"
)

func main() {
	// Get some CEF events to parse
	cefEvents := []string{
		parser.ImpervaCEF1,
		parser.ImpervaCEF5,
		parser.CentrifyCEF,
	}

	// Example 1: Use standard parser
	fmt.Println("=== Standard Parser ===")
	standardParser := parser.NewParser(parser.DefaultConfig())
	parseWithBenchmark(standardParser, cefEvents)

	// Example 2: Use fast parser
	fmt.Println("\n=== Fast Parser ===")
	fastConfig := parser.FastConfig()
	fastParser := parser.NewParser(fastConfig)
	parseWithBenchmark(fastParser, cefEvents)

	// Example 3: Use safe parser
	fmt.Println("\n=== Safe Parser ===")
	safeConfig := parser.SafeConfig()
	safeParser := parser.NewParser(safeConfig)
	parseWithBenchmark(safeParser, cefEvents)

	// Example 4: Handling errors with diagnostics
	fmt.Println("\n=== Error Diagnostics ===")
	badCEF := "CEF:0|Vendor|Product|Version|ID|Name|7"
	_, err := safeParser.Parse(badCEF)
	fmt.Printf("Error: %v\n", err)

	// Example 5: Batch processing
	fmt.Println("\n=== Batch Processing ===")
	start := time.Now()
	results, errors := fastParser.BatchParse(cefEvents)
	elapsed := time.Since(start)
	fmt.Printf("Batch processed %d events in %s\n", len(results), elapsed)
	for i, result := range results {
		if errors[i] != nil {
			fmt.Printf("Error parsing event %d: %v\n", i, errors[i])
		} else {
			fmt.Printf("Event %d: %s %s\n", i, result.DeviceVendor, result.Name)
			// Return the object to the pool
			fastParser.Release(result)
		}
	}

	// Example 6: Parser metrics
	fmt.Println("\n=== Parser Metrics ===")
	metrics := fastParser.GetMetrics()
	for key, value := range metrics {
		fmt.Printf("%s: %d\n", key, value)
	}
}

// parseWithBenchmark parses all events and measures performance
func parseWithBenchmark(p parser.Parser, events []string) {
	// Reset metrics
	p.ResetMetrics()

	// Measure memory before
	var memStatsBefore, memStatsAfter runtime.MemStats
	runtime.ReadMemStats(&memStatsBefore)

	// Parse events
	start := time.Now()
	for _, event := range events {
		cef, err := p.Parse(event)
		if err != nil {
			fmt.Printf("Parse error: %v\n", err)
			continue
		}
		fmt.Printf("Parsed: %s | %s\n", cef.DeviceVendor, cef.Name)
		p.Release(cef)
	}
	elapsed := time.Since(start)

	// Measure memory after
	runtime.ReadMemStats(&memStatsAfter)
	allocatedBytes := memStatsAfter.TotalAlloc - memStatsBefore.TotalAlloc

	// Metrics
	metrics := p.GetMetrics()
	fmt.Printf("Parsed %d events in %s\n", metrics[parser.MetricParsed], elapsed)
	fmt.Printf("Memory allocated: %d bytes\n", allocatedBytes)

	// Output config
	config := p.GetConfig()
	fmt.Printf("Parser mode: %v, Validation level: %v\n", config.Mode, config.Validation)
}
