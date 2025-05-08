// Package parser provides functionality for parsing CEF events.
package parser

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// testMode is used to control extension type selection for testing
var testMode bool = false

// EnableTestMode enables test mode, which uses standard extension types instead of fast variants
func EnableTestMode() {
	testMode = true
}

// DisableTestMode disables test mode, returning to production extension types
func DisableTestMode() {
	testMode = false
}

// NewExtensions returns an Extensions struct based on the vendor, product, and version.
func NewExtensions(vendor, product, version string) Extensions {
	switch {
	case vendor == "Incapsula" && product == "SIEMintegration":
		if testMode {
			return &ImpervaExtensions{}
		}
		return NewImpervaExtensionsFast()
	case vendor == "Centrify" && product == "Centrify_Cloud":
		return &CentrifyExtensions{}
	default:
		return &DefaultExtensions{}
	}
}

// cefObjectPool provides object pooling for CEF structs.
var cefObjectPool = sync.Pool{
	New: func() interface{} {
		return &CEF{}
	},
}

// Release returns a CEF object to the object pool for reuse.
// Call this function when you are done with a CEF object to reduce memory allocations.
func Release(cef *CEF) {
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
}

// ParseCEF parses a CEF event string into a CEF struct.
func ParseCEF(cef string) (*CEF, error) {
	return ParseCEFWithDefault(cef)
}

// ParseFastCEF is a high-performance alternative to ParseCEF.
// Uses a pooled CEF object and optimized parsing for maximum throughput.
func ParseFastCEF(cef string) (*CEF, error) {
	fastParser := NewParser(FastConfig())
	return fastParser.Parse(cef)
}

// ParseCEFWithContext parses a CEF event string into a CEF struct, supporting context for cancellations and timeouts.
func ParseCEFWithContext(ctx context.Context, cef string) (*CEF, error) {
	return ParseCEFWithContextDefault(ctx, cef)
}

// ParseFastCEFWithContext is a high-performance alternative to ParseCEFWithContext.
// Uses a pooled CEF object and optimized parsing for maximum throughput.
func ParseFastCEFWithContext(ctx context.Context, cef string) (*CEF, error) {
	fastParser := NewParser(FastConfig())
	return fastParser.ParseWithContext(ctx, cef)
}

// splitCEFHeader splits a CEF string into its header components using optimized methods.
// Returns string slices that are backed by the original string data to avoid allocations.
func splitCEFHeader(s string) ([]string, error) {
	result := make([]string, 0, 8)

	// Fast path for common case, unescaped pipe characters
	var lastIdx, count int

	// Track escaping state
	escaped := false

	// Scan the string once, splitting on unescaped pipes
	for i := 0; i < len(s); i++ {
		if escaped {
			escaped = false
			continue
		}

		if s[i] == '\\' {
			escaped = true
			continue
		}

		if s[i] == '|' {
			// Add the substring to the result
			result = append(result, s[lastIdx:i])
			lastIdx = i + 1
			count++

			// We expect 7 pipes (8 fields)
			if count == 7 {
				// Add the rest of the string as the last part (extensions)
				if i+1 < len(s) {
					result = append(result, s[i+1:])
				} else {
					result = append(result, "")
				}
				return result, nil
			}
		}
	}

	// If we get here, we didn't find enough pipes
	return nil, fmt.Errorf("invalid CEF format: expected 7 pipes, found %d", count)
}

// parseExtensions parses the key-value pairs in the extension string.
func parseExtensions(extension string) map[string]string {
	result := make(map[string]string)

	// Split the extension part on spaces that are not inside quotes
	var inQuotes bool
	var escaped bool
	var currentPart []byte
	var currentKey string

	for i := 0; i < len(extension); i++ {
		c := extension[i]

		// Handle escaped characters
		if escaped {
			currentPart = append(currentPart, c)
			escaped = false
			continue
		}
		if c == '\\' {
			currentPart = append(currentPart, c)
			escaped = true
			continue
		}

		// Handle quotes
		if c == '"' {
			inQuotes = !inQuotes
			currentPart = append(currentPart, c)
			continue
		}

		// Handle key-value separation
		if c == '=' && len(currentKey) == 0 && !inQuotes {
			currentKey = string(currentPart)
			currentPart = nil
			continue
		}

		// Handle space as delimiter outside of quotes
		if c == ' ' && !inQuotes {
			if len(currentKey) > 0 {
				result[currentKey] = string(currentPart)
				currentKey = ""
				currentPart = nil
			} else if len(currentPart) > 0 {
				// This would be malformed (space without a previous =)
				currentPart = nil
			}
			continue
		}

		// Add character to current part
		currentPart = append(currentPart, c)
	}

	// Handle the last key-value pair
	if len(currentKey) > 0 && len(currentPart) > 0 {
		result[currentKey] = string(currentPart)
	}

	return result
}

// isValidCEFComponent ensures that each CEF component is valid.
func isValidCEFComponent(component string) bool {
	// Validate length and ensure no forbidden characters
	return len(component) > 0 && len(component) <= 100 && regexp.MustCompile(`^[a-zA-Z0-9_ .()-]+$`).MatchString(component)
}

// isValidCEFKey checks if a key in the extensions is valid.
func isValidCEFKey(key string) bool {
	// Keys should be alphanumeric and can contain underscores
	// Adjust this regex as needed based on CEF specification
	return len(key) > 0 && len(key) <= 50 && regexp.MustCompile(`^[a-zA-Z0-9_]+$`).MatchString(key)
}

// isValidCEFValue checks if a value in the extensions is valid.
func isValidCEFValue(value string) bool {
	// Values can be more permissive, but still have length limits
	// Check for any obviously dangerous content
	return len(value) <= 1000 && !strings.Contains(value, "\x00") // No null bytes
}
