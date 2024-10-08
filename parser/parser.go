// Package parser provides functionality for parsing CEF events.
package parser

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// NewExtensions returns an Extensions struct based on the vendor, product, and version.
func NewExtensions(vendor, product, version string) Extensions {
	switch {
	case vendor == "Incapsula" && product == "SIEMintegration":
		return &ImpervaExtensions{}
	case vendor == "Centrify" && product == "Centrify_Cloud":
		return &CentrifyExtensions{}
	default:
		return &DefaultExtensions{}
	}
}

// ParseCEF parses a CEF event string into a CEF struct.
func ParseCEF(cef string) (*CEF, error) {
	return ParseCEFWithContext(context.Background(), cef)
}

// ParseCEFWithContext parses a CEF event string into a CEF struct, supporting context for cancellations and timeouts.
func ParseCEFWithContext(ctx context.Context, cef string) (*CEF, error) {
	// Basic input validation before parsing
	if len(cef) == 0 || len(cef) > 10000 {
		return nil, fmt.Errorf("invalid CEF string length")
	}

	regex := regexp.MustCompile(`^CEF:([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|(.*)$`)
	matches := regex.FindStringSubmatch(cef)

	if len(matches) == 0 {
		return nil, fmt.Errorf("invalid CEF format")
	}

	// Further validation on parsed fields
	if !isValidCEFComponent(matches[1]) || !isValidCEFComponent(matches[2]) ||
		!isValidCEFComponent(matches[3]) || !isValidCEFComponent(matches[4]) ||
		!isValidCEFComponent(matches[5]) || !isValidCEFComponent(matches[6]) ||
		!isValidCEFComponent(matches[7]) {
		return nil, fmt.Errorf("one or more CEF components are invalid")
	}

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

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		extension := matches[8]
		cefEvent.Extensions.ParseExtensions(extension)
	}

	return cefEvent, nil
}

// parseExtensions parses a CEF extension string into a map.
func parseExtensions(extension string) map[string]string {
	var keyValPairs = make(map[string]string)
	var currentKey string
	var currentVal string
	var isValueComplex bool
	var complexValBuilder strings.Builder

	parts := strings.Split(extension, " ")

	for _, part := range parts {
		if strings.Contains(part, "=") && !isValueComplex {
			if currentKey != "" && currentVal != "" {
				keyValPairs[currentKey] = strings.Trim(currentVal, `"`)
			}
			parts := strings.SplitN(part, "=", 2)
			currentKey = parts[0]
			currentVal = parts[1]

			// Handle JSON-like and complex structures
			if strings.HasPrefix(currentVal, "\"") && !strings.HasSuffix(currentVal, "\"") {
				isValueComplex = true
				complexValBuilder.WriteString(currentVal)
			} else if strings.HasPrefix(currentVal, "[{") && !strings.HasSuffix(currentVal, "}]") {
				isValueComplex = true
				complexValBuilder.WriteString(currentVal)
			}
		} else {
			if isValueComplex {
				complexValBuilder.WriteString(" ")
				complexValBuilder.WriteString(part)
				if (strings.HasPrefix(complexValBuilder.String(), "\"") && strings.HasSuffix(part, "\"")) ||
					(strings.HasPrefix(complexValBuilder.String(), "[{") && strings.HasSuffix(part, "}]")) {
					isValueComplex = false
					currentVal = complexValBuilder.String()
					complexValBuilder.Reset()
				}
			} else {
				currentVal += " " + part
			}
		}
	}

	if currentKey != "" && currentVal != "" {
		keyValPairs[currentKey] = strings.Trim(currentVal, `"`)
	}

	return keyValPairs
}

// isValidCEFComponent ensures that each CEF component is valid.
func isValidCEFComponent(component string) bool {
	// Validate length and ensure no forbidden characters
	return len(component) > 0 && len(component) <= 100 && regexp.MustCompile(`^[a-zA-Z0-9_ .-]+$`).MatchString(component)
}

// isValidCEFKey validates if the CEF key conforms to expected patterns.
func isValidCEFKey(key string) bool {
	// Implement more complex validation if necessary
	if len(key) == 0 || len(key) > 50 {
		return false
	}
	// Ensure the key contains only allowed characters
	return regexp.MustCompile(`^[a-zA-Z0-9_]+$`).MatchString(key)
}

// isValidCEFValue validates the CEF value for length and content.
func isValidCEFValue(value string) bool {
	// Implement more complex validation if necessary
	if len(value) == 0 || len(value) > 1000 {
		return false
	}
	// Basic check to ensure there are no unexpected characters
	return true
}
