// main.go demonstrates how to extract specific fields from Imperva CEF events.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ren3gadem4rm0t/cef-parser-go/parser"
)

// RequestData represents key information extracted from a CEF event
type RequestData struct {
	Timestamp      string      `json:"timestamp"`
	SourceIP       string      `json:"source_ip"`
	DestinationIP  string      `json:"destination_ip"`
	Request        string      `json:"request"`
	RequestMethod  string      `json:"request_method"`
	StatusCode     string      `json:"status_code"`
	UserAgent      string      `json:"user_agent"`
	Country        string      `json:"country"`
	City           string      `json:"city"`
	Latitude       string      `json:"latitude"`
	Longitude      string      `json:"longitude"`
	Action         string      `json:"action"`
	RuleInfo       interface{} `json:"rule_info,omitempty"`
	ProcessingTime string      `json:"processing_time,omitempty"`
	BytesIn        string      `json:"bytes_in,omitempty"`
	TLSVersion     string      `json:"tls_version,omitempty"`
	XForwardedFor  []string    `json:"x_forwarded_for,omitempty"`
}

// extractRequestData extracts key information from a CEF event into a structured format
func extractRequestData(cef *parser.CEF) (*RequestData, error) {
	data := &RequestData{}

	// Extract string fields with fallbacks for missing values
	extractStringField := func(cef *parser.CEF, fieldName string) string {
		if val, err := cef.Extensions.GetField(fieldName); err == nil {
			if strVal, ok := val.(string); ok {
				return strVal
			}
		}
		return ""
	}

	// Get basic fields
	data.Timestamp = extractStringField(cef, "Start")
	data.SourceIP = extractStringField(cef, "SIP")
	data.DestinationIP = extractStringField(cef, "Src")
	data.Request = extractStringField(cef, "Request")
	data.RequestMethod = extractStringField(cef, "RequestMethod")
	data.StatusCode = extractStringField(cef, "CN1")
	data.UserAgent = extractStringField(cef, "RequestClientApplication")
	data.Country = extractStringField(cef, "CCCode")
	data.City = extractStringField(cef, "CICode")
	data.Latitude = extractStringField(cef, "CS7")
	data.Longitude = extractStringField(cef, "CS8")
	data.Action = extractStringField(cef, "Act")
	data.ProcessingTime = extractStringField(cef, "CPT")
	data.BytesIn = extractStringField(cef, "In")
	data.TLSVersion = extractStringField(cef, "Ver")

	// Extract XFF (X-Forwarded-For) IPs
	if xff, err := cef.Extensions.GetField("XFF"); err == nil {
		if xffSlice, ok := xff.([]string); ok {
			data.XForwardedFor = xffSlice
		}
	}

	// Extract rule information (potentially complex JSON structure)
	if ruleInfo, err := cef.Extensions.GetField("CS10"); err == nil {
		data.RuleInfo = ruleInfo
	}

	return data, nil
}

func main() {
	// Open the log file
	file, err := os.Open("examples/realworld/extract_fields/1076_15376344.log")
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Printf("Error closing file: %v\n", err)
		}
	}()

	// Create a scanner for the file
	scanner := bufio.NewScanner(file)

	// Create a buffer for the scanner to handle potentially long lines
	const maxCapacity = 1024 * 1024 // 1MB
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	// Process only the first few events
	fmt.Println("Extracting data from the first 5 CEF events:")
	count := 0

	for scanner.Scan() && count < 5 {
		line := scanner.Text()

		// Only process CEF lines
		if strings.HasPrefix(line, "CEF:") {
			cefEvent, err := parser.ParseCEF(line)
			if err != nil {
				fmt.Printf("Error parsing CEF: %v\n", err)
				continue
			}

			// Extract structured data
			data, err := extractRequestData(cefEvent)
			if err != nil {
				fmt.Printf("Error extracting data: %v\n", err)
				parser.Release(cefEvent)
				continue
			}

			// Convert data to JSON for display
			jsonData, err := json.MarshalIndent(data, "", "  ")
			if err != nil {
				fmt.Printf("Error marshaling to JSON: %v\n", err)
				parser.Release(cefEvent)
				continue
			}

			// Print the JSON data
			fmt.Printf("Event %d:\n%s\n\n", count+1, string(jsonData))
			count++

			// Release the CEF event back to the pool
			parser.Release(cefEvent)
		}
	}

	// Check for scanner errors
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file: %v\n", err)
	}
}
