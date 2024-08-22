// Package parser provides functionality for parsing CEF events.
package parser

import (
	"encoding/json"
	"fmt"
	"reflect"
)

// CentrifyExtensions represents the specific extension fields for Centrify.
type CentrifyExtensions struct {
	DHost              string
	DUser              string
	Msg                string
	SHost              string
	Src                string
	RT                 string
	DeviceProcessName  string
	DvcHost            string
	DTZ                string
	RequestContext     string
	ExternalID         string
	DPriv              string
	DestinationService string
	SUID               string
	CS1                string
	CS1Label           string
	CS2                string
	CS2Label           string
	CS3                string
	CS3Label           string
	CS4                string
	CS4Label           string
	CS5                string
	CS5Label           string
	CS6                string
	CS6Label           string
}

// ParseExtensions parses the extension string into the CentrifyExtensions struct.
func (ce *CentrifyExtensions) ParseExtensions(extension string) map[string]string {
	fields := parseExtensions(extension)
	ce.DHost = fields["dhost"]
	ce.DUser = fields["duser"]
	ce.Msg = fields["msg"]
	ce.SHost = fields["shost"]
	ce.Src = fields["src"]
	ce.RT = fields["rt"]
	ce.DeviceProcessName = fields["deviceProcessName"]
	ce.DvcHost = fields["dvchost"]
	ce.DTZ = fields["dtz"]
	ce.RequestContext = fields["requestContext"]
	ce.ExternalID = fields["externalId"]
	ce.DPriv = fields["dpriv"]
	ce.DestinationService = fields["destinationServiceName"]
	ce.SUID = fields["suid"]
	ce.CS1 = fields["cs1"]
	ce.CS1Label = fields["cs1Label"]
	ce.CS2 = fields["cs2"]
	ce.CS2Label = fields["cs2Label"]
	ce.CS3 = fields["cs3"]
	ce.CS3Label = fields["cs3Label"]
	ce.CS4 = fields["cs4"]
	ce.CS4Label = fields["cs4Label"]
	ce.CS5 = fields["cs5"]
	ce.CS5Label = fields["cs5Label"]
	ce.CS6 = fields["cs6"]
	ce.CS6Label = fields["cs6Label"]
	return fields
}

// GetField dynamically retrieves a field value by name using reflection.
func (ce *CentrifyExtensions) GetField(fieldName string) (interface{}, error) {
	r := reflect.ValueOf(ce)
	f := reflect.Indirect(r).FieldByName(fieldName)
	if f.IsValid() {
		return f.Interface(), nil
	}
	return nil, fmt.Errorf("field %s not found", fieldName)
}

// AsJSON returns the extension fields as a pretty JSON string.
func (ce *CentrifyExtensions) AsJSON() string {
	data, _ := json.MarshalIndent(ce, "", "  ")
	return string(data)
}

// AsMap returns the extension fields as a map.
func (ce *CentrifyExtensions) AsMap() map[string]string {
	return structToMap(ce)
}

// GetFieldNames returns the field names of the extension.
func (ce *CentrifyExtensions) GetFieldNames() []string {
	return getFieldNames(ce)
}
