// Package parser provides functionality for parsing CEF events.
package parser

import (
	"context"
	"io"
	"sync"
)

// Parser defines a unified interface for parsing CEF events
type Parser interface {
	// Parse parses a single CEF event string
	Parse(cefString string) (*CEF, error)

	// ParseWithContext parses a single CEF event string with context for cancellation
	ParseWithContext(ctx context.Context, cefString string) (*CEF, error)

	// ParseStream parses CEF events from an io.Reader
	ParseStream(reader io.Reader, handler func(*CEF, error) bool) error

	// ParseStreamWithContext parses CEF events from an io.Reader with context for cancellation
	ParseStreamWithContext(ctx context.Context, reader io.Reader, handler func(*CEF, error) bool) error

	// BatchParse parses multiple CEF events at once
	BatchParse(cefStrings []string) ([]*CEF, []error)

	// Release returns a CEF object to the pool if pooling is enabled
	Release(cef *CEF)

	// GetConfig returns the parser configuration
	GetConfig() ParserConfig

	// ResetMetrics resets any metrics collected by the parser
	ResetMetrics()

	// GetMetrics returns metrics collected by the parser
	GetMetrics() map[string]uint64
}

// NewParser creates a new parser with the given configuration
func NewParser(config ParserConfig) Parser {
	switch config.Mode {
	case ModeFast:
		return &FastParser{
			config:  config,
			metrics: make(map[string]uint64),
		}
	case ModeSafe:
		return &SafeParser{
			config:  config,
			metrics: make(map[string]uint64),
		}
	case ModeStandard:
		return &StandardParser{
			config:  config,
			metrics: make(map[string]uint64),
		}
	default: // ModeAuto
		// Choose based on config settings
		if config.UsePooling && config.Validation == ValidationMinimal {
			return &FastParser{
				config:  config,
				metrics: make(map[string]uint64),
			}
		} else if config.Validation == ValidationFull {
			return &SafeParser{
				config:  config,
				metrics: make(map[string]uint64),
			}
		} else {
			return &StandardParser{
				config:  config,
				metrics: make(map[string]uint64),
			}
		}
	}
}

// StandardParser implements the Parser interface using the standard parser
type StandardParser struct {
	config       ParserConfig
	metrics      map[string]uint64
	metricsMutex sync.RWMutex
}

// FastParser implements the Parser interface using the fast parser
type FastParser struct {
	config       ParserConfig
	metrics      map[string]uint64
	metricsMutex sync.RWMutex
}

// SafeParser implements the Parser interface with additional validation
type SafeParser struct {
	config       ParserConfig
	metrics      map[string]uint64
	metricsMutex sync.RWMutex
}

// Global parser instance with default configuration
var defaultParser Parser = NewParser(DefaultConfig())

// GlobalParser returns the global parser instance
func GlobalParser() Parser {
	return defaultParser
}

// SetGlobalParser sets the global parser instance
func SetGlobalParser(parser Parser) {
	defaultParser = parser
}

// ParseCEFWithDefault parses a CEF string using the global parser
func ParseCEFWithDefault(cefString string) (*CEF, error) {
	return defaultParser.Parse(cefString)
}

// ParseCEFWithContextDefault parses a CEF string with context using the global parser
func ParseCEFWithContextDefault(ctx context.Context, cefString string) (*CEF, error) {
	return defaultParser.ParseWithContext(ctx, cefString)
}

// Stream parser for reading CEF events from a stream
type CEFStreamParser struct {
	reader io.Reader
	parser Parser
}

// NewCEFStreamParser creates a new CEF stream parser
func NewCEFStreamParser(reader io.Reader, config ParserConfig) *CEFStreamParser {
	return &CEFStreamParser{
		reader: reader,
		parser: NewParser(config),
	}
}
