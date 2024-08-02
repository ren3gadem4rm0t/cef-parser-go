// Package parser provides functionality for parsing CEF events.
package parser

import (
	"reflect"
	"strings"
)

// getFieldNames returns the field names of a struct.
func getFieldNames(obj interface{}) []string {
	val := reflect.ValueOf(obj).Elem()
	typ := val.Type()
	var fieldNames []string

	for i := 0; i < val.NumField(); i++ {
		fieldNames = append(fieldNames, typ.Field(i).Name)
	}

	return fieldNames
}

// structToMap converts a struct to a map with string keys and values.
func structToMap(obj interface{}) map[string]string {
	val := reflect.ValueOf(obj).Elem()
	typ := val.Type()
	fields := make(map[string]string)

	for i := 0; i < val.NumField(); i++ {
		fieldName := typ.Field(i).Name
		fieldValue := val.Field(i).Interface()
		if strValue, ok := fieldValue.(string); ok {
			fields[strings.ToLower(fieldName)] = strValue
		}
	}

	return fields
}

// removeCEFEscapeChars normalizes strings that contain backlashes.
// Particularly useful for JSON strings with unnecessary escapes.
func removeCEFEscapeChars(s string) string {
	// remove escape for `=`
	s = strings.Replace(s, `\=`, "=", -1)
	return s
}
