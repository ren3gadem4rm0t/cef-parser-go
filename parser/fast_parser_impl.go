// Package parser provides functionality for parsing CEF events.
package parser

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
)

// FastParser implementation

// Parse parses a CEF string
func (p *FastParser) Parse(cefString string) (*CEF, error) {
	return p.ParseWithContext(context.Background(), cefString)
}

// ParseWithContext parses a CEF string with context
func (p *FastParser) ParseWithContext(ctx context.Context, cefString string) (*CEF, error) {
	// Apply max size limitation
	if len(cefString) == 0 || len(cefString) > p.config.MaxEventSize {
		if p.config.EnableMetrics {
			p.incrementMetric(MetricErrors)
		}
		return nil, fmt.Errorf("invalid CEF string length")
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// Continue processing
	}

	// Verify the string starts with CEF:
	if len(cefString) < 4 || cefString[:4] != "CEF:" {
		if p.config.EnableMetrics {
			p.incrementMetric(MetricErrors)
		}
		return nil, fmt.Errorf("invalid CEF format: must start with CEF")
	}

	// Get a CEF object from the pool
	cefEvent := cefObjectPool.Get().(*CEF)
	// Reset fields to zero values
	*cefEvent = CEF{}

	// Fast split by pipe character to parse header
	parts, err := splitCEFHeader(cefString)
	if err != nil {
		cefObjectPool.Put(cefEvent) // Return object to pool on error
		if p.config.EnableMetrics {
			p.incrementMetric(MetricErrors)
		}
		return nil, err
	}

	// Process parts into CEF struct
	cefEvent.Version = parts[0][4:] // Skip "CEF:"
	cefEvent.DeviceVendor = parts[1]
	cefEvent.DeviceProduct = parts[2]
	cefEvent.DeviceVersion = parts[3]
	cefEvent.SignatureID = parts[4]
	cefEvent.Name = parts[5]
	cefEvent.Severity = parts[6]

	// Get a fresh extension implementation based on vendor/product
	cefEvent.Extensions = NewExtensions(parts[1], parts[2], parts[3])

	// Parse extension fields (everything after last pipe)
	if len(parts) > 7 && len(parts[7]) > 0 {
		select {
		case <-ctx.Done():
			cefObjectPool.Put(cefEvent) // Return object to pool on context cancellation
			return nil, ctx.Err()
		default:
			cefEvent.Extensions.ParseExtensions(parts[7])
		}
	}

	// Update metrics
	if p.config.EnableMetrics {
		p.incrementMetric(MetricParsed)
		p.addMetric(MetricBytesProcessed, uint64(len(cefString)))
	}

	return cefEvent, nil
}

// ParseStream parses CEF events from a reader
func (p *FastParser) ParseStream(reader io.Reader, handler func(*CEF, error) bool) error {
	return p.ParseStreamWithContext(context.Background(), reader, handler)
}

// ParseStreamWithContext parses CEF events from a reader with context
func (p *FastParser) ParseStreamWithContext(ctx context.Context, reader io.Reader, handler func(*CEF, error) bool) error {
	// Create a buffered reader with a larger buffer for performance
	bufReader := bufio.NewReaderSize(reader, 64*1024) // 64KB buffer

	// Use a scanner for line reading
	scanner := bufio.NewScanner(bufReader)

	// Set larger buffer if configured
	if p.config.MaxEventSize > bufio.MaxScanTokenSize {
		buf := make([]byte, p.config.MaxEventSize)
		scanner.Buffer(buf, p.config.MaxEventSize)
	}

	// Process each line
	for scanner.Scan() {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Continue processing
		}

		line := scanner.Text()
		if !strings.HasPrefix(line, "CEF:") {
			continue
		}

		cef, err := p.ParseWithContext(ctx, line)
		if !handler(cef, err) {
			break
		}
	}

	return scanner.Err()
}

// BatchParse parses multiple CEF events
func (p *FastParser) BatchParse(cefStrings []string) ([]*CEF, []error) {
	cefs := make([]*CEF, len(cefStrings))
	errs := make([]error, len(cefStrings))

	// Use goroutines to parallelize parsing
	numWorkers := 4 // Adjust based on your needs
	jobs := make(chan int, len(cefStrings))

	var wg sync.WaitGroup

	// Create worker goroutines
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				cefs[i], errs[i] = p.Parse(cefStrings[i])
			}
		}()
	}

	// Send jobs to workers
	for i := range cefStrings {
		jobs <- i
	}
	close(jobs)

	// Wait for all workers to finish
	wg.Wait()

	return cefs, errs
}

// Release returns a CEF object to the pool
func (p *FastParser) Release(cef *CEF) {
	if cef == nil {
		return
	}

	// Handle extensions that can be returned to their own pools
	if pool, ok := cef.Extensions.(interface{ ReturnToPool() }); ok {
		pool.ReturnToPool()
	}

	// Reset the CEF object to zero values
	*cef = CEF{}

	// Return it to the pool
	cefObjectPool.Put(cef)

	if p.config.EnableMetrics {
		p.incrementMetric(MetricObjectsReleased)
	}
}

// GetConfig returns the parser configuration
func (p *FastParser) GetConfig() ParserConfig {
	return p.config
}

// ResetMetrics resets the parser metrics
func (p *FastParser) ResetMetrics() {
	p.metricsMutex.Lock()
	defer p.metricsMutex.Unlock()
	p.metrics = make(map[string]uint64)
}

// GetMetrics returns the parser metrics
func (p *FastParser) GetMetrics() map[string]uint64 {
	p.metricsMutex.RLock()
	defer p.metricsMutex.RUnlock()

	// Create a copy to prevent race conditions
	result := make(map[string]uint64, len(p.metrics))
	for k, v := range p.metrics {
		result[k] = v
	}

	return result
}

// incrementMetric safely increments a metric
func (p *FastParser) incrementMetric(name string) {
	p.metricsMutex.Lock()
	defer p.metricsMutex.Unlock()
	val := p.metrics[name]
	p.metrics[name] = val + 1
}

// addMetric safely adds a value to a metric
func (p *FastParser) addMetric(name string, value uint64) {
	p.metricsMutex.Lock()
	defer p.metricsMutex.Unlock()
	val := p.metrics[name]
	p.metrics[name] = val + value
}
