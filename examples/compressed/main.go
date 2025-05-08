// Package main demonstrates how to process compressed Imperva CEF logs.
package main

import (
	"bufio"
	"compress/gzip"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ren3gadem4rm0t/cef-parser-go/parser"
)

// Configuration options for the log processor
type config struct {
	inputFile      string
	outputFormat   string
	maxWorkers     int
	filterVendor   string
	filterProduct  string
	filterSeverity string
	verbose        bool
	noStats        bool
	profile        bool
	gomaxprocs     int
	bufferSize     int
}

// Statistics for processed logs
type stats struct {
	totalLines       int64
	parsedLines      int64
	errorLines       int64
	startTime        time.Time
	endTime          time.Time
	uniqueVendors    map[string]int
	uniqueProducts   map[string]int
	uniqueSeverities map[string]int
	mu               sync.Mutex
}

func main() {
	cfg := parseFlags()

	// Configure GOMAXPROCS if specified
	if cfg.gomaxprocs > 0 {
		runtime.GOMAXPROCS(cfg.gomaxprocs)
	}

	// Start CPU profiling if requested
	if cfg.profile {
		f, err := os.Create("cpu.prof")
		if err != nil {
			log.Fatal(err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}

	if cfg.verbose {
		log.Printf("Starting processing of file: %s", cfg.inputFile)
		log.Printf("Using %d worker goroutines", cfg.maxWorkers)
		log.Printf("GOMAXPROCS: %d", runtime.GOMAXPROCS(0))
	}

	// Initialize statistics
	stats := &stats{
		startTime:        time.Now(),
		uniqueVendors:    make(map[string]int),
		uniqueProducts:   make(map[string]int),
		uniqueSeverities: make(map[string]int),
	}

	// Process the file
	err := processGzippedFile(cfg, stats)
	if err != nil {
		log.Fatalf("Error processing file: %v", err)
	}

	// Calculate duration
	stats.endTime = time.Now()
	duration := stats.endTime.Sub(stats.startTime)

	if !cfg.noStats {
		// Print statistics
		fmt.Printf("\nProcessing complete!\n")
		fmt.Printf("Processed %d lines in %v\n", stats.totalLines, duration)
		fmt.Printf("Successfully parsed: %d lines\n", stats.parsedLines)
		fmt.Printf("Errors: %d lines\n", stats.errorLines)
		fmt.Printf("Processing speed: %.2f lines/sec\n", float64(stats.totalLines)/duration.Seconds())

		if cfg.verbose {
			fmt.Printf("\nUnique Vendors: %d\n", len(stats.uniqueVendors))
			for vendor, count := range stats.uniqueVendors {
				fmt.Printf("  %s: %d\n", vendor, count)
			}

			fmt.Printf("\nUnique Products: %d\n", len(stats.uniqueProducts))
			for product, count := range stats.uniqueProducts {
				fmt.Printf("  %s: %d\n", product, count)
			}

			fmt.Printf("\nSeverity Distribution:\n")
			for severity, count := range stats.uniqueSeverities {
				fmt.Printf("  %s: %d\n", severity, count)
			}
		}
	}
}

// parseFlags parses command line flags and returns a config struct
func parseFlags() *config {
	cfg := &config{}

	// Default to the sample file in this directory
	defaultFile := filepath.Join("examples", "compressed", "5282_10116173.log.gz")

	flag.StringVar(&cfg.inputFile, "file", defaultFile, "Path to the gzipped CEF log file")
	flag.StringVar(&cfg.outputFormat, "format", "summary", "Output format: summary, json, or detailed")
	flag.IntVar(&cfg.maxWorkers, "workers", runtime.NumCPU()*2, "Maximum number of worker goroutines")
	flag.StringVar(&cfg.filterVendor, "vendor", "", "Filter by vendor (case sensitive)")
	flag.StringVar(&cfg.filterProduct, "product", "", "Filter by product (case sensitive)")
	flag.StringVar(&cfg.filterSeverity, "severity", "", "Filter by severity")
	flag.BoolVar(&cfg.verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&cfg.noStats, "nostats", false, "Disable statistics output")
	flag.BoolVar(&cfg.profile, "profile", false, "Enable CPU profiling")
	flag.IntVar(&cfg.gomaxprocs, "gomaxprocs", 0, "Set GOMAXPROCS (default: use Go runtime default)")
	flag.IntVar(&cfg.bufferSize, "buffer", 10000, "Size of processing buffer")

	flag.Parse()

	// If no flags were provided and the default file doesn't exist,
	// check if the file exists relative to the current directory
	if flag.NFlag() == 0 && !fileExists(cfg.inputFile) {
		localFile := "5282_10116173.log.gz"
		if fileExists(localFile) {
			cfg.inputFile = localFile
		}
	}

	return cfg
}

// fileExists checks if a file exists
func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

// processGzippedFile opens and processes a gzipped CEF log file
func processGzippedFile(cfg *config, stats *stats) error {
	// Open the gzipped file
	file, err := os.Open(cfg.inputFile)
	if err != nil {
		return fmt.Errorf("could not open file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Printf("Error closing file: %v", err)
		}
	}()

	// Create a gzip reader
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("could not create gzip reader: %w", err)
	}
	defer func() {
		if err := gzReader.Close(); err != nil {
			log.Printf("Error closing gzip reader: %v", err)
		}
	}()

	// Channel to hold lines for processing
	lineChan := make(chan string, cfg.bufferSize)

	// WaitGroup to keep track of goroutines
	var wg sync.WaitGroup

	// Start worker goroutines to process lines
	for i := 0; i < cfg.maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Local statistics counters for batch updates
			localParsed := 0
			localErrors := 0
			localVendors := make(map[string]int)
			localProducts := make(map[string]int)
			localSeverities := make(map[string]int)

			// Define the update frequency to reduce lock contention
			const updateFrequency = 100
			processedCount := 0

			for line := range lineChan {
				// Skip lines that don't start with CEF:
				if !strings.HasPrefix(line, "CEF:") {
					continue
				}

				// Parse the CEF log entry
				cefEvent, err := parser.ParseCEF(line)
				if err != nil {
					localErrors++
					if cfg.verbose {
						log.Printf("Error parsing line: %v", err)
					}
					continue
				}

				// Apply filters
				if cfg.filterVendor != "" && cefEvent.DeviceVendor != cfg.filterVendor {
					continue
				}
				if cfg.filterProduct != "" && cefEvent.DeviceProduct != cfg.filterProduct {
					continue
				}
				if cfg.filterSeverity != "" && cefEvent.Severity != cfg.filterSeverity {
					continue
				}

				// Update local statistics
				localParsed++
				localVendors[cefEvent.DeviceVendor]++
				localProducts[cefEvent.DeviceProduct]++
				localSeverities[cefEvent.Severity]++

				// Output the CEF event
				outputCEF(cefEvent, cfg.outputFormat)

				// Return the CEF object to the pool when done
				parser.Release(cefEvent)

				// Periodically update global statistics to reduce lock contention
				processedCount++
				if processedCount >= updateFrequency {
					stats.mu.Lock()
					stats.parsedLines += int64(localParsed)
					stats.errorLines += int64(localErrors)

					// Update maps
					for vendor, count := range localVendors {
						stats.uniqueVendors[vendor] += count
					}
					for product, count := range localProducts {
						stats.uniqueProducts[product] += count
					}
					for severity, count := range localSeverities {
						stats.uniqueSeverities[severity] += count
					}
					stats.mu.Unlock()

					// Reset local counters
					localParsed = 0
					localErrors = 0
					localVendors = make(map[string]int)
					localProducts = make(map[string]int)
					localSeverities = make(map[string]int)
					processedCount = 0
				}
			}

			// Update any remaining statistics
			if localParsed > 0 || localErrors > 0 {
				stats.mu.Lock()
				stats.parsedLines += int64(localParsed)
				stats.errorLines += int64(localErrors)

				// Update maps
				for vendor, count := range localVendors {
					stats.uniqueVendors[vendor] += count
				}
				for product, count := range localProducts {
					stats.uniqueProducts[product] += count
				}
				for severity, count := range localSeverities {
					stats.uniqueSeverities[severity] += count
				}
				stats.mu.Unlock()
			}
		}()
	}

	// Read the lines from the file and send them to workers
	scanner := bufio.NewScanner(gzReader)
	// Set a larger scanner buffer to handle long lines
	const maxCapacity = 2 * 1024 * 1024 // 2MB
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	// Use atomic counter for total lines to avoid lock contention
	var totalLines int64

	for scanner.Scan() {
		// Get the line text
		line := scanner.Text()

		// Fast path: pre-check if the line begins with CEF: before queuing
		if !strings.HasPrefix(line, "CEF:") {
			atomic.AddInt64(&totalLines, 1)
			continue
		}

		// Send the line to a worker
		lineChan <- line
		atomic.AddInt64(&totalLines, 1)
	}

	// Check if there was an error during scanning
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	// Close the channel to signal that no more lines are coming
	close(lineChan)

	// Wait for all worker goroutines to finish
	wg.Wait()

	// Update total line count
	stats.totalLines = totalLines

	return nil
}

// outputCEF formats and outputs a CEF event based on the specified format
func outputCEF(cefEvent *parser.CEF, format string) {
	switch format {
	case "json":
		fmt.Println(cefEvent.AsJSON())
	case "detailed":
		fmt.Printf("CEF Version: %s\n", cefEvent.Version)
		fmt.Printf("Vendor: %s\n", cefEvent.DeviceVendor)
		fmt.Printf("Product: %s\n", cefEvent.DeviceProduct)
		fmt.Printf("Version: %s\n", cefEvent.DeviceVersion)
		fmt.Printf("Signature ID: %s\n", cefEvent.SignatureID)
		fmt.Printf("Name: %s\n", cefEvent.Name)
		fmt.Printf("Severity: %s\n", cefEvent.Severity)

		// Get extension field names
		fieldNames := cefEvent.Extensions.GetFieldNames()
		fmt.Printf("Extension Fields (%d):\n", len(fieldNames))
		for _, name := range fieldNames {
			value, _ := cefEvent.Extensions.GetField(name)
			fmt.Printf("  %s: %v\n", name, value)
		}
		fmt.Println(strings.Repeat("-", 80))
	case "summary":
		fmt.Printf("%s|%s|%s|%s|%s\n",
			cefEvent.DeviceVendor,
			cefEvent.DeviceProduct,
			cefEvent.Name,
			cefEvent.Severity,
			getFieldSummary(cefEvent),
		)
	default:
		fmt.Println(cefEvent.AsJSON())
	}
}

// getFieldSummary returns a summary of important fields in the CEF event
func getFieldSummary(cefEvent *parser.CEF) string {
	var summary strings.Builder

	// Retrieve common fields that are useful in summaries
	commonFields := []string{"sip", "spt", "dip", "dpt", "src", "dst", "request", "requestMethod", "act", "cn1", "app", "xff", "deviceFacility", "Customer"}

	for _, field := range commonFields {
		value, err := cefEvent.Extensions.GetField(field)
		if err == nil && value != "" {
			summary.WriteString(fmt.Sprintf("%s=%s ", field, value))
		}
	}

	return summary.String()
}
