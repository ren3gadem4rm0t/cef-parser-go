// Package parser provides functionality for parsing CEF events.
package parser

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Error types for better diagnostics
var (
	ErrInvalidLength    = errors.New("invalid CEF string length")
	ErrInvalidFormat    = errors.New("invalid CEF format")
	ErrInvalidComponent = errors.New("one or more CEF components are invalid")
	ErrInvalidExtension = errors.New("invalid extension format")
	ErrContextCanceled  = errors.New("operation canceled by context")
)

// DiagnosticError combines an error with additional diagnostic information
type DiagnosticError struct {
	Err        error
	Component  string
	Value      string
	LineNumber int
	Position   int
	Context    string
}

// Error implements the error interface for DiagnosticError
func (e *DiagnosticError) Error() string {
	if e.Component != "" {
		return fmt.Sprintf("%s: invalid component '%s' with value '%s'", e.Err.Error(), e.Component, e.Value)
	}
	if e.LineNumber > 0 {
		return fmt.Sprintf("%s at line %d position %d: %s", e.Err.Error(), e.LineNumber, e.Position, e.Context)
	}
	return e.Err.Error()
}

// Unwrap returns the underlying error
func (e *DiagnosticError) Unwrap() error {
	return e.Err
}

// SafeParser implementation

// Parse parses a CEF string
func (p *SafeParser) Parse(cefString string) (*CEF, error) {
	return p.ParseWithContext(context.Background(), cefString)
}

// ParseWithContext parses a CEF string with context
func (p *SafeParser) ParseWithContext(ctx context.Context, cefString string) (*CEF, error) {
	// Apply max size limitation with detailed error
	if len(cefString) == 0 {
		err := &DiagnosticError{
			Err:     ErrInvalidLength,
			Context: "empty string",
		}
		p.incrementMetric(MetricErrors)
		return nil, err
	}

	if len(cefString) > p.config.MaxEventSize {
		err := &DiagnosticError{
			Err:     ErrInvalidLength,
			Context: fmt.Sprintf("length %d exceeds maximum %d", len(cefString), p.config.MaxEventSize),
		}
		p.incrementMetric(MetricErrors)
		return nil, err
	}

	// Check context cancellation
	select {
	case <-ctx.Done():
		err := &DiagnosticError{
			Err:     ErrContextCanceled,
			Context: ctx.Err().Error(),
		}
		return nil, err
	default:
		// Continue processing
	}

	// Verify CEF format
	if !strings.HasPrefix(cefString, "CEF:") {
		err := &DiagnosticError{
			Err:     ErrInvalidFormat,
			Context: "missing CEF: prefix",
		}
		p.incrementMetric(MetricErrors)
		return nil, err
	}

	// Apply the strict validation regex
	matches := fullValidationRegex.FindStringSubmatch(cefString)
	if len(matches) == 0 {
		// Try to provide more context about the error
		pipeCount := strings.Count(cefString, "|")
		err := &DiagnosticError{
			Err:     ErrInvalidFormat,
			Context: fmt.Sprintf("found %d pipes, expected 7", pipeCount),
		}
		p.incrementMetric(MetricErrors)
		return nil, err
	}

	// Detailed validation of each component
	components := []string{"Version", "DeviceVendor", "DeviceProduct", "DeviceVersion", "SignatureID", "Name", "Severity"}
	for i, component := range components {
		if !isValidCEFComponent(matches[i+1]) {
			err := &DiagnosticError{
				Err:       ErrInvalidComponent,
				Component: component,
				Value:     matches[i+1],
			}
			p.incrementMetric(MetricValidationErrs)
			return nil, err
		}
	}

	// Create CEF object - never pool in safe mode
	cefEvent := &CEF{
		Version:       matches[1],
		DeviceVendor:  matches[2],
		DeviceProduct: matches[3],
		DeviceVersion: matches[4],
		SignatureID:   matches[5],
		Name:          matches[6],
		Severity:      matches[7],
		Extensions:    NewExtensions(matches[2], matches[3], matches[4]),
	}

	// Parse extensions with validation
	if len(matches) > 8 && len(matches[8]) > 0 {
		select {
		case <-ctx.Done():
			err := &DiagnosticError{
				Err:     ErrContextCanceled,
				Context: ctx.Err().Error(),
			}
			return nil, err
		default:
			ext := matches[8]

			// Validate extension format
			if !p.validateExtensionFormat(ext) {
				err := &DiagnosticError{
					Err:     ErrInvalidExtension,
					Context: "invalid key-value format",
				}
				p.incrementMetric(MetricErrors)
				return nil, err
			}

			cefEvent.Extensions.ParseExtensions(ext)
		}
	}

	// Update metrics
	p.incrementMetric(MetricParsed)
	p.addMetric(MetricBytesProcessed, uint64(len(cefString)))

	return cefEvent, nil
}

// ParseStream parses CEF events from a reader with extra validation
func (p *SafeParser) ParseStream(reader io.Reader, handler func(*CEF, error) bool) error {
	return p.ParseStreamWithContext(context.Background(), reader, handler)
}

// ParseStreamWithContext parses CEF events from a reader with context and extra validation
func (p *SafeParser) ParseStreamWithContext(ctx context.Context, reader io.Reader, handler func(*CEF, error) bool) error {
	scanner := bufio.NewScanner(reader)

	// Use conservative buffer size
	buf := make([]byte, 8192) // Start with 8KB
	scanner.Buffer(buf, p.config.MaxEventSize)

	lineNumber := 0

	// Process each line
	for scanner.Scan() {
		lineNumber++

		// Check context cancellation
		select {
		case <-ctx.Done():
			return &DiagnosticError{
				Err:     ErrContextCanceled,
				Context: ctx.Err().Error(),
			}
		default:
			// Continue processing
		}

		line := scanner.Text()
		if !strings.HasPrefix(line, "CEF:") {
			// Skip non-CEF lines silently
			continue
		}

		cef, err := p.ParseWithContext(ctx, line)
		if err != nil {
			// Add line number info to errors
			if diagErr, ok := err.(*DiagnosticError); ok {
				diagErr.LineNumber = lineNumber
			}
		}

		if !handler(cef, err) {
			break
		}
	}

	// Handle scanner errors with context
	if err := scanner.Err(); err != nil {
		return &DiagnosticError{
			Err:     err,
			Context: "error reading input",
		}
	}

	return nil
}

// BatchParse parses multiple CEF events with added safety
func (p *SafeParser) BatchParse(cefStrings []string) ([]*CEF, []error) {
	cefs := make([]*CEF, len(cefStrings))
	errs := make([]error, len(cefStrings))

	// In safe mode, always process sequentially
	for i, cefString := range cefStrings {
		cefs[i], errs[i] = p.Parse(cefString)
	}

	return cefs, errs
}

// Release returns a CEF object to the pool
func (p *SafeParser) Release(cef *CEF) {
	// In safe mode, we don't pool objects
	// Let the garbage collector handle them
	p.incrementMetric(MetricObjectsReleased)
}

// GetConfig returns the parser configuration
func (p *SafeParser) GetConfig() ParserConfig {
	return p.config
}

// ResetMetrics resets the parser metrics
func (p *SafeParser) ResetMetrics() {
	p.metricsMutex.Lock()
	defer p.metricsMutex.Unlock()
	p.metrics = make(map[string]uint64)
}

// GetMetrics returns the parser metrics
func (p *SafeParser) GetMetrics() map[string]uint64 {
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
func (p *SafeParser) incrementMetric(name string) {
	p.metricsMutex.Lock()
	defer p.metricsMutex.Unlock()
	val := p.metrics[name]
	p.metrics[name] = val + 1
}

// addMetric safely adds a value to a metric
func (p *SafeParser) addMetric(name string, value uint64) {
	p.metricsMutex.Lock()
	defer p.metricsMutex.Unlock()
	val := p.metrics[name]
	p.metrics[name] = val + value
}

// validateExtensionFormat performs additional validation on extension format
func (p *SafeParser) validateExtensionFormat(extensions string) bool {
	// Minimal validation - check for key=value format with proper spacing
	parts := strings.Split(extensions, " ")
	for _, part := range parts {
		if part == "" {
			continue
		}

		// Each non-empty part should contain = character
		if !strings.Contains(part, "=") {
			return false
		}
	}

	return true
}
