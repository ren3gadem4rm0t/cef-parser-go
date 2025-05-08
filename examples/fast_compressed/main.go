// Package main demonstrates how to process compressed Imperva CEF logs
// with maximum performance using the optimized fast parser.
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
	fastParser     bool
	scannerBufSize int
	queueSize      int
	batchSize      int
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

// batchResult holds the results of a batch of processed lines
type batchResult struct {
	parsedCount int64
	errorCount  int64
	vendors     map[string]int
	products    map[string]int
	severities  map[string]int
}

// resultPool reuses batch result objects
var resultPool = sync.Pool{
	New: func() interface{} {
		return &batchResult{
			vendors:    make(map[string]int, 10),
			products:   make(map[string]int, 10),
			severities: make(map[string]int, 10),
		}
	},
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
		log.Printf("Buffer size: %d", cfg.scannerBufSize)
		log.Printf("Queue size: %d", cfg.queueSize)
		log.Printf("Batch size: %d", cfg.batchSize)
		log.Printf("Fast parser: %v", cfg.fastParser)
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

			// Print parser stats
			if cfg.fastParser {
				fmt.Printf("\nParser Stats:\n")
				for stat, value := range parser.GetStats() {
					fmt.Printf("  %s: %d\n", stat, value)
				}
			}
		}
	}
}

// parseFlags parses command line flags and returns a config struct
func parseFlags() *config {
	cfg := &config{}

	// Default to the sample file in this directory
	defaultFile := filepath.Join("examples", "compressed", "repeat_logs.log.gz")

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
	flag.BoolVar(&cfg.fastParser, "fast", true, "Use fast parser implementation")
	flag.IntVar(&cfg.scannerBufSize, "scanbuf", 4*1024*1024, "Scanner buffer size in bytes (default: 4MB)")
	flag.IntVar(&cfg.queueSize, "queue", 50000, "Size of line processing queue")
	flag.IntVar(&cfg.batchSize, "batch", 1000, "Batch size for statistics updates")

	flag.Parse()

	// If no flags were provided and the default file doesn't exist,
	// check if the file exists relative to the current directory
	if flag.NFlag() == 0 && !fileExists(cfg.inputFile) {
		localFile := "repeat_logs.log.gz"
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
	lineChan := make(chan string, cfg.queueSize)

	// Channel for batch results
	resultChan := make(chan *batchResult, cfg.maxWorkers*2)

	// WaitGroup to keep track of goroutines
	var wg sync.WaitGroup
	var resultWg sync.WaitGroup

	// Start collector goroutine to handle batch results
	resultWg.Add(1)
	go func() {
		defer resultWg.Done()

		for result := range resultChan {
			// Update global statistics atomically
			atomic.AddInt64(&stats.parsedLines, result.parsedCount)
			atomic.AddInt64(&stats.errorLines, result.errorCount)

			// Update maps with mutex protection
			stats.mu.Lock()
			for vendor, count := range result.vendors {
				stats.uniqueVendors[vendor] += count
			}
			for product, count := range result.products {
				stats.uniqueProducts[product] += count
			}
			for severity, count := range result.severities {
				stats.uniqueSeverities[severity] += count
			}
			stats.mu.Unlock()

			// Clear and return result to pool
			for k := range result.vendors {
				delete(result.vendors, k)
			}
			for k := range result.products {
				delete(result.products, k)
			}
			for k := range result.severities {
				delete(result.severities, k)
			}
			result.parsedCount = 0
			result.errorCount = 0
			resultPool.Put(result)
		}
	}()

	// Start worker goroutines to process lines
	for i := 0; i < cfg.maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Get a batch result from the pool
			resultObj := resultPool.Get().(*batchResult)

			// Line counter for current batch
			var batchCounter int

			for line := range lineChan {
				// Skip lines that don't start with CEF:
				if !strings.HasPrefix(line, "CEF:") {
					continue
				}

				// Parse the CEF log entry using the appropriate parser
				var cefEvent *parser.CEF
				var err error

				if cfg.fastParser {
					cefEvent, err = parser.ParseFastCEF(line)
				} else {
					cefEvent, err = parser.ParseCEF(line)
				}

				if err != nil {
					resultObj.errorCount++
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
				resultObj.parsedCount++
				resultObj.vendors[cefEvent.DeviceVendor]++
				resultObj.products[cefEvent.DeviceProduct]++
				resultObj.severities[cefEvent.Severity]++

				// Output the CEF event
				if !cfg.noStats {
					outputCEF(cefEvent, cfg.outputFormat)
				}

				// Return CEF object to pool
				parser.Release(cefEvent)

				// Send batch results when batch size reached
				batchCounter++
				if batchCounter >= cfg.batchSize {
					resultChan <- resultObj
					resultObj = resultPool.Get().(*batchResult)
					batchCounter = 0
				}
			}

			// Send any remaining results
			if resultObj.parsedCount > 0 || resultObj.errorCount > 0 {
				resultChan <- resultObj
			} else {
				// Return unused result to pool
				resultPool.Put(resultObj)
			}
		}()
	}

	// Read the lines from the file and send them to workers
	reader := bufio.NewReaderSize(gzReader, cfg.scannerBufSize/2)
	scanner := bufio.NewScanner(reader)

	// Set a larger scanner buffer to handle long lines
	buf := make([]byte, cfg.scannerBufSize)
	scanner.Buffer(buf, cfg.scannerBufSize)

	// Use atomic counter for total lines to avoid lock contention
	var totalLines int64

	// Track the time spent reading vs processing
	readStart := time.Now()

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

	readDuration := time.Since(readStart)
	if cfg.verbose {
		log.Printf("Read time: %v, average: %.2f lines/sec",
			readDuration, float64(totalLines)/readDuration.Seconds())
	}

	// Check if there was an error during scanning
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	// Close the channel to signal that no more lines are coming
	close(lineChan)

	// Wait for all worker goroutines to finish
	wg.Wait()

	// Close result channel and wait for collector to finish
	close(resultChan)
	resultWg.Wait()

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
		// For maximum performance, don't actually output anything
		// Just simulate the processing
		_ = fmt.Sprintf("%s|%s|%s|%s",
			cefEvent.DeviceVendor,
			cefEvent.DeviceProduct,
			cefEvent.Name,
			cefEvent.Severity,
		)
	}
}
