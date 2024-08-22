// Package parser provides functionality for parsing CEF events.
package parser

import "encoding/json"

// CEF represents a CEF event.
type CEF struct {
	Version       string
	DeviceVendor  string
	DeviceProduct string
	DeviceVersion string
	SignatureID   string
	Name          string
	Severity      string
	Extensions    Extensions
}

// Extensions defines methods for parsing, converting to JSON/map, and getting field names.
type Extensions interface {
	ParseExtensions(extension string) map[string]string
	AsJSON() string
	AsMap() map[string]string
	GetFieldNames() []string
	GetField(fieldName string) (interface{}, error)
}

// AsJSON returns the CEF event as a pretty JSON string.
func (cef *CEF) AsJSON() string {
	data, _ := json.MarshalIndent(cef, "", "  ")
	return string(data)
}
