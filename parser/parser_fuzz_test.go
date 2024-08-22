// parser_fuzz_test.go
package parser

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// FuzzParseCEF is a fuzz test for the ParseCEF function.
func FuzzParseCEF(f *testing.F) {
	f.Add(ImpervaCEF1)
	f.Add(CentrifyCEF)
	f.Add(ImpervaCEFCombined)

	f.Fuzz(func(t *testing.T, data string) {
		_, err := ParseCEFWithContext(context.Background(), data)
		if err != nil {
			t.Logf("Error parsing CEF: %v", err)
		}
	})
}

// FuzzParseExtensions is a fuzz test for the parseExtensions function.
func FuzzParseExtensions(f *testing.F) {
	f.Add("fileId=123 sourceServiceName=example siteid=123")
	f.Fuzz(func(t *testing.T, data string) {
		parseExtensions(data)
	})
}

// FuzzAsJSON is a fuzz test for the AsJSON method in the CEF struct.
func FuzzAsJSON(f *testing.F) {
	cef := &CEF{
		Version:       "0",
		DeviceVendor:  "ExampleVendor",
		DeviceProduct: "ExampleProduct",
		DeviceVersion: "1.0",
		SignatureID:   "1000",
		Name:          "TestEvent",
		Severity:      "5",
		Extensions:    &DefaultExtensions{Fields: map[string]string{"key": "value"}},
	}

	f.Fuzz(func(t *testing.T, data string) {
		cef.DeviceVendor = data
		cef.AsJSON()
	})
}

// FuzzStructuredCEF is a structured fuzz test for the ParseCEF function.
func FuzzStructuredCEF(f *testing.F) {
	f.Add("Incapsula", "SIEMintegration", "1", "Sample CEF Event")

	f.Fuzz(func(t *testing.T, vendor, product, version, name string) {
		cef := "CEF:0|" + vendor + "|" + product + "|" + version + "|1000|" + name + "|5|"
		_, err := ParseCEFWithContext(context.Background(), cef)
		if err != nil {
			t.Logf("Error parsing structured CEF: %v", err)
		}
	})
}

// FuzzSecurityCEF is a security-focused fuzz test for CEF parsing.
func FuzzSecurityCEF(f *testing.F) {
	// SQL Injection attempt
	f.Add(`CEF:0|Vendor|Product|1.0|1000|TestEvent|5|fileid=' OR '1'='1`)
	// Cross-Site Scripting (XSS) attempt
	f.Add(`CEF:0|Incapsula|SIEMintegration|1|1|<script>alert(1)</script>|3| fileid=<img src=x onerror=alert(1)>`)
	// Command Injection attempt
	f.Add(`CEF:0|Vendor|Product|1.0|1000|TestEvent|5|fileid=|touch /tmp/evilfile`)
	// Log Forging attempt
	f.Add(`CEF:0|Vendor|Product|1.0|1000|TestEvent|5|fileid=maliciousValue\nSecondEvent|malicious|attack`)
	// JSON Injection attempt
	f.Add(`CEF:0|Vendor|Product|1.0|1000|TestEvent|5|fileid={"key":"value"}`)
	// Large JSON object to test for JSON parsing limits and possible memory exhaustion
	f.Add(`CEF:0|Vendor|Product|1.0|1000|TestEvent|5|fileid={"key":` + strings.Repeat(`"value",`, 10000) + `"last":"value"}`)
	// Nested JSON structure to test recursion limits
	f.Add(`CEF:0|Vendor|Product|1.0|1000|TestEvent|5|fileid=` + nestedJSON(100))
	// JSON with special characters that may escape JSON string boundaries
	f.Add(`CEF:0|Vendor|Product|1.0|1000|TestEvent|5|fileid="\u202Eevil\json\u202C"`)
	// JSON with null bytes to test if Go properly handles them
	f.Add(`CEF:0|Vendor|Product|1.0|1000|TestEvent|5|fileid="\u0000"`)
	// JSON with extremely deep nesting to test stack overflows or panics
	f.Add(`CEF:0|Vendor|Product|1.0|1000|TestEvent|5|fileid=` + deeplyNestedJSON(10000))

	// Fuzz testing with random inputs to simulate other potential security issues
	f.Fuzz(func(t *testing.T, data string) {
		cefEvent, err := ParseCEFWithContext(context.Background(), data)
		if err != nil {
			t.Logf("Security test triggered error: %v", err)
		}

		// Additional checks to ensure that fields are properly sanitized
		if cefEvent != nil && cefEvent.Extensions != nil {
			jsonOutput := cefEvent.AsJSON()
			if len(jsonOutput) == 0 {
				t.Errorf("JSON output is empty for input: %s", data)
			}
			if !isValidJSON(jsonOutput) {
				t.Errorf("JSON output is malformed for input: %s", data)
			}
		}
	})
}

// isValidJSON checks if the string is valid JSON.
func isValidJSON(s string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(s), &js) == nil
}

// nestedJSON creates a nested JSON string for testing.
func nestedJSON(depth int) string {
	json := `{"key":`
	for i := 0; i < depth; i++ {
		json += `{"key":`
	}
	json += `"value"`
	for i := 0; i < depth; i++ {
		json += `}`
	}
	return json + `}`
}

// deeplyNestedJSON creates a deeply nested JSON string for testing recursion limits.
func deeplyNestedJSON(depth int) string {
	json := `{"key":`
	for i := 0; i < depth; i++ {
		json += `{"nested":`
	}
	json += `"deep_value"`
	for i := 0; i < depth; i++ {
		json += `}`
	}
	return json + `}`
}
