// Package parser provides functionality for parsing CEF events.
package parser

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
)

// StandardParser implementation

// Parse parses a CEF string
func (p *StandardParser) Parse(cefString string) (*CEF, error) {
	return p.ParseWithContext(context.Background(), cefString)
}

// ParseWithContext parses a CEF string with context
func (p *StandardParser) ParseWithContext(ctx context.Context, cefString string) (*CEF, error) {
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

	// Create or get regex based on validation level
	var regex *regexp.Regexp
	switch p.config.Validation {
	case ValidationFull:
		regex = fullValidationRegex
	case ValidationMinimal:
		regex = minimalValidationRegex
	default: // ValidationBasic
		regex = basicValidationRegex
	}

	// Parse the CEF string
	matches := regex.FindStringSubmatch(cefString)
	if len(matches) == 0 {
		if p.config.EnableMetrics {
			p.incrementMetric(MetricErrors)
		}
		return nil, fmt.Errorf("invalid CEF format")
	}

	// Additional validation based on validation level
	if p.config.Validation != ValidationMinimal {
		if !isValidCEFComponent(matches[1]) || !isValidCEFComponent(matches[2]) ||
			!isValidCEFComponent(matches[3]) || !isValidCEFComponent(matches[4]) ||
			!isValidCEFComponent(matches[5]) || !isValidCEFComponent(matches[6]) ||
			!isValidCEFComponent(matches[7]) {
			if p.config.EnableMetrics {
				p.incrementMetric(MetricValidationErrs)
			}
			return nil, fmt.Errorf("one or more CEF components are invalid")
		}
	}

	// Create CEF object
	var cefEvent *CEF
	if p.config.UsePooling {
		cefEvent = cefObjectPool.Get().(*CEF)
		// Reset fields to zero values
		*cefEvent = CEF{}
	} else {
		cefEvent = &CEF{}
	}

	// Fill CEF object
	cefEvent.Version = matches[1]
	cefEvent.DeviceVendor = matches[2]
	cefEvent.DeviceProduct = matches[3]
	cefEvent.DeviceVersion = matches[4]
	cefEvent.SignatureID = matches[5]
	cefEvent.Name = matches[6]
	cefEvent.Severity = matches[7]

	// Create extensions
	cefEvent.Extensions = NewExtensions(matches[2], matches[3], matches[4])

	// Parse extensions
	if len(matches) > 8 && len(matches[8]) > 0 {
		select {
		case <-ctx.Done():
			if p.config.UsePooling {
				cefObjectPool.Put(cefEvent) // Return object to pool on error
			}
			return nil, ctx.Err()
		default:
			cefEvent.Extensions.ParseExtensions(matches[8])
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
func (p *StandardParser) ParseStream(reader io.Reader, handler func(*CEF, error) bool) error {
	return p.ParseStreamWithContext(context.Background(), reader, handler)
}

// ParseStreamWithContext parses CEF events from a reader with context
func (p *StandardParser) ParseStreamWithContext(ctx context.Context, reader io.Reader, handler func(*CEF, error) bool) error {
	scanner := bufio.NewScanner(reader)

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
func (p *StandardParser) BatchParse(cefStrings []string) ([]*CEF, []error) {
	cefs := make([]*CEF, len(cefStrings))
	errs := make([]error, len(cefStrings))

	// For safety mode, process sequentially
	if p.config.Mode == ModeSafe {
		for i, cefString := range cefStrings {
			cefs[i], errs[i] = p.Parse(cefString)
		}
		return cefs, errs
	}

	// Otherwise process in parallel
	var wg sync.WaitGroup
	wg.Add(len(cefStrings))

	for i, cefString := range cefStrings {
		go func(i int, cefString string) {
			defer wg.Done()
			cefs[i], errs[i] = p.Parse(cefString)
		}(i, cefString)
	}

	wg.Wait()
	return cefs, errs
}

// Release returns a CEF object to the pool
func (p *StandardParser) Release(cef *CEF) {
	if cef == nil || !p.config.UsePooling {
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
func (p *StandardParser) GetConfig() ParserConfig {
	return p.config
}

// ResetMetrics resets the parser metrics
func (p *StandardParser) ResetMetrics() {
	p.metricsMutex.Lock()
	defer p.metricsMutex.Unlock()
	p.metrics = make(map[string]uint64)
}

// GetMetrics returns the parser metrics
func (p *StandardParser) GetMetrics() map[string]uint64 {
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
func (p *StandardParser) incrementMetric(name string) {
	p.metricsMutex.Lock()
	defer p.metricsMutex.Unlock()
	val, _ := p.metrics[name]
	p.metrics[name] = val + 1
}

// addMetric safely adds a value to a metric
func (p *StandardParser) addMetric(name string, value uint64) {
	p.metricsMutex.Lock()
	defer p.metricsMutex.Unlock()
	val, _ := p.metrics[name]
	p.metrics[name] = val + value
}

// Pre-compiled regexes for different validation levels
var (
	// Full validation regex with strict format checking
	fullValidationRegex = regexp.MustCompile(`^CEF:([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|(.*)$`)

	// Basic validation regex with standard format checking
	basicValidationRegex = regexp.MustCompile(`^CEF:([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|(.*)$`)

	// Minimal validation regex for maximum performance
	minimalValidationRegex = regexp.MustCompile(`^CEF:([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|(.*)$`)
)
