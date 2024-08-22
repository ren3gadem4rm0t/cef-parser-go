// Package parser provides functionality for parsing CEF events.
package parser

import (
	"encoding/json"
	"fmt"
)

// DefaultExtensions provides a generic implementation of the Extensions interface.
type DefaultExtensions struct {
	Fields map[string]string
}

// ParseExtensions parses the extension string into a map.
func (de *DefaultExtensions) ParseExtensions(extension string) map[string]string {
	de.Fields = parseExtensions(extension)
	return de.Fields
}

// GetField dynamically retrieves a field value by name.
func (de *DefaultExtensions) GetField(fieldName string) (interface{}, error) {
	if value, ok := de.Fields[fieldName]; ok {
		return value, nil
	}
	return nil, fmt.Errorf("field %s not found", fieldName)
}

// AsJSON returns the extension fields as a pretty JSON string.
func (de *DefaultExtensions) AsJSON() string {
	data, _ := json.MarshalIndent(de.Fields, "", "  ")
	return string(data)
}

// AsMap returns the extension fields as a map.
func (de *DefaultExtensions) AsMap() map[string]string {
	return de.Fields
}

// GetFieldNames returns the field names of the extension.
func (de *DefaultExtensions) GetFieldNames() []string {
	fieldNames := make([]string, 0, len(de.Fields))
	for k := range de.Fields {
		fieldNames = append(fieldNames, k)
	}
	return fieldNames
}
