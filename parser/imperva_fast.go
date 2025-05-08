// Package parser provides functionality for parsing CEF events.
package parser

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
)

// ImpervaExtensionsFast is a high-performance implementation of ImpervaExtensions.
type ImpervaExtensionsFast struct {
	ImpervaExtensions // Embed the original struct for compatibility
	extensionsMap     map[string]string
}

// ImpervaExtensionsFastPool maintains a pool of ImpervaExtensionsFast objects to reduce allocations.
var ImpervaExtensionsFastPool = sync.Pool{
	New: func() interface{} {
		ie := &ImpervaExtensionsFast{
			extensionsMap: make(map[string]string, 64), // Pre-allocate with reasonable capacity
		}
		return ie
	},
}

// NewImpervaExtensionsFast returns a new instance from the pool.
func NewImpervaExtensionsFast() *ImpervaExtensionsFast {
	return ImpervaExtensionsFastPool.Get().(*ImpervaExtensionsFast)
}

// ReturnToPool returns the instance to the pool for reuse.
func (ie *ImpervaExtensionsFast) ReturnToPool() {
	// Clear all maps and slices
	for k := range ie.extensionsMap {
		delete(ie.extensionsMap, k)
	}

	// Reset all fields to zero values
	*ie = ImpervaExtensionsFast{
		extensionsMap: ie.extensionsMap,
	}

	// Return to pool
	ImpervaExtensionsFastPool.Put(ie)
}

// ParseExtensions parses the extension string using highly optimized methods.
func (ie *ImpervaExtensionsFast) ParseExtensions(extension string) map[string]string {
	// Fast state machine parser
	fields := fastParseExtensions(extension)
	ie.extensionsMap = fields

	// Map fields to struct
	ie.FileID = fields["fileId"]
	ie.SourceServiceName = fields["sourceServiceName"]
	ie.SiteID = fields["siteid"]
	ie.SUID = fields["suid"]
	ie.RequestClientApplication = fields["requestClientApplication"]
	ie.DeviceFacility = fields["deviceFacility"]
	ie.CS2 = fields["cs2"]
	ie.CS2Label = fields["cs2Label"]
	ie.CS3 = fields["cs3"]
	ie.CS3Label = fields["cs3Label"]
	ie.CS1 = fields["cs1"]
	ie.CS1Label = fields["cs1Label"]
	ie.CS4 = fields["cs4"]
	ie.CS4Label = fields["cs4Label"]
	ie.CS5 = fields["cs5"]
	ie.CS5Label = fields["cs5Label"]
	ie.DProc = fields["dproc"]
	ie.CS6 = fields["cs6"]
	ie.CS6Label = fields["cs6Label"]
	ie.CCCode = fields["ccode"]
	ie.CS7 = fields["cs7"]
	ie.CS7Label = fields["cs7Label"]
	ie.CS8 = fields["cs8"]
	ie.CS8Label = fields["cs8Label"]
	ie.CS9 = fields["cs9"]
	ie.CS9Label = fields["cs9Label"]
	ie.Customer = fields["Customer"]
	ie.Start = fields["start"]
	ie.Request = fields["request"]
	ie.Ref = fields["ref"]
	ie.RequestMethod = fields["requestMethod"]
	ie.CN1 = fields["cn1"]
	ie.App = fields["app"]
	ie.Act = fields["act"]
	ie.DeviceExternalID = fields["deviceExternalId"]
	ie.SIP = fields["sip"]
	ie.SPT = fields["spt"]
	ie.In = fields["in"]

	// Specialized field handling
	xffValue, hasXff := fields["xff"]
	if hasXff && xffValue != "" {
		ie.XFF = strings.Split(xffValue, ", ")
	}

	// Handle JSON fields with optimized parsing to reduce errors
	// Fix: Make a copy of the JSON data to prevent race conditions during concurrent unmarshaling
	if additionalResHeaders, ok := fields["additionalResHeaders"]; ok && len(additionalResHeaders) > 0 {
		// Process JSON with proper escaping
		processedJSON, _ := preprocessJSON(additionalResHeaders)
		var jsonData interface{}
		// Make a copy to prevent race conditions
		jsonBytes := []byte(processedJSON)
		if json.Unmarshal(jsonBytes, &jsonData) == nil {
			ie.AdditionalResHeaders = jsonData
		} else {
			ie.AdditionalResHeaders = additionalResHeaders
		}
	}

	if additionalReqHeaders, ok := fields["additionalReqHeaders"]; ok && len(additionalReqHeaders) > 0 {
		// Process JSON with proper escaping
		processedJSON, _ := preprocessJSON(additionalReqHeaders)
		var jsonData interface{}
		// Make a copy to prevent race conditions
		jsonBytes := []byte(processedJSON)
		if json.Unmarshal(jsonBytes, &jsonData) == nil {
			ie.AdditionalReqHeaders = jsonData
		} else {
			ie.AdditionalReqHeaders = additionalReqHeaders
		}
	}

	// Process cs10 (common source of errors) with special handling
	if cs10, ok := fields["cs10"]; ok && len(cs10) > 0 {
		// Clean and process JSON data
		processedJSON, _ := preprocessJSON(cs10)
		var jsonData interface{}
		// Make a copy to prevent race conditions
		jsonBytes := []byte(processedJSON)
		if json.Unmarshal(jsonBytes, &jsonData) == nil {
			ie.CS10 = jsonData
		} else {
			ie.CS10 = cs10
		}
	}

	if cs11, ok := fields["cs11"]; ok && len(cs11) > 0 {
		// Process JSON with proper escaping
		processedJSON, _ := preprocessJSON(cs11)
		var jsonData interface{}
		// Make a copy to prevent race conditions
		jsonBytes := []byte(processedJSON)
		if json.Unmarshal(jsonBytes, &jsonData) == nil {
			ie.CS11 = jsonData
		} else {
			ie.CS11 = cs11
		}
	}

	ie.CS10Label = fields["cs10Label"]
	ie.CS11Label = fields["cs11Label"]
	ie.CPT = fields["cpt"]
	ie.Src = fields["src"]
	ie.Ver = fields["ver"]
	ie.End = fields["end"]

	return fields
}

// GetField dynamically retrieves a field value by name using reflection.
func (ie *ImpervaExtensionsFast) GetField(fieldName string) (interface{}, error) {
	// Try the fast path first using the map directly
	if value, ok := ie.extensionsMap[fieldName]; ok {
		return value, nil
	}

	// Fall back to reflection for struct fields
	r := reflect.ValueOf(ie)
	f := reflect.Indirect(r).FieldByName(fieldName)
	if f.IsValid() {
		return f.Interface(), nil
	}

	return nil, fmt.Errorf("field %s not found", fieldName)
}

// AsJSON returns the extension fields as a pretty JSON string.
func (ie *ImpervaExtensionsFast) AsJSON() string {
	data, _ := json.MarshalIndent(ie, "", "  ")
	return string(data)
}

// AsMap returns the extension fields as a map.
func (ie *ImpervaExtensionsFast) AsMap() map[string]string {
	return ie.extensionsMap
}

// GetFieldNames returns the field names of the extension.
func (ie *ImpervaExtensionsFast) GetFieldNames() []string {
	result := make([]string, 0, len(ie.extensionsMap))
	for k := range ie.extensionsMap {
		result = append(result, k)
	}
	return result
}
