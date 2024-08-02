// Package parser provides functionality for parsing CEF events.
package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

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

// ImpervaExtensions represents the specific extension fields for Imperva.
type ImpervaExtensions struct {
	FileID                   string
	SourceServiceName        string
	SiteID                   string
	SUID                     string
	RequestClientApplication string
	DeviceFacility           string
	CS2                      string
	CS2Label                 string
	CS3                      string
	CS3Label                 string
	CS1                      string
	CS1Label                 string
	CS4                      string
	CS4Label                 string
	CS5                      string
	CS5Label                 string
	DProc                    string
	CS6                      string
	CS6Label                 string
	CCCode                   string
	CS7                      string
	CS7Label                 string
	CS8                      string
	CS8Label                 string
	CS9                      string
	CS9Label                 string
	AdditionalReqHeaders     interface{}
	AdditionalResHeaders     interface{}
	Customer                 string
	Start                    string
	Request                  string
	Ref                      string
	RequestMethod            string
	CN1                      string
	App                      string
	Act                      string
	DeviceExternalID         string
	SIP                      string
	SPT                      string
	In                       string
	XFF                      []string
	CS10                     interface{}
	CS10Label                string
	CS11                     interface{}
	CS11Label                string
	CPT                      string
	Src                      string
	Ver                      string
	End                      string
}

// ParseExtensions parses the extension string into the ImpervaExtensions struct.
func (ie *ImpervaExtensions) ParseExtensions(extension string) map[string]string {
	fields := parseExtensions(extension)
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
	ie.XFF = strings.Split(fields["xff"], ", ")
	ie.CS10 = fields["cs10"]
	ie.CS10Label = fields["cs10Label"]
	ie.CS11 = fields["cs11"]
	ie.CS11Label = fields["cs11Label"]
	ie.CPT = fields["cpt"]
	ie.Src = fields["src"]
	ie.Ver = fields["ver"]
	ie.End = fields["end"]

	if additionalResHeaders, ok := fields["additionalResHeaders"]; ok {
		additionalResHeaders = removeCEFEscapeChars(additionalResHeaders)
		var additionalResHeadersJSON interface{}
		if err := json.Unmarshal([]byte(additionalResHeaders), &additionalResHeadersJSON); err == nil {
			ie.AdditionalResHeaders = additionalResHeadersJSON
		} else {
			ie.AdditionalResHeaders = additionalResHeaders
		}
	}

	if additionalReqHeaders, ok := fields["additionalReqHeaders"]; ok {
		additionalReqHeaders = removeCEFEscapeChars(additionalReqHeaders)
		var additionalReqHeadersJSON interface{}
		if err := json.Unmarshal([]byte(additionalReqHeaders), &additionalReqHeadersJSON); err == nil {
			ie.AdditionalReqHeaders = additionalReqHeadersJSON
		} else {
			ie.AdditionalReqHeaders = additionalReqHeaders
		}
	}

	if cs10, ok := fields["cs10"]; ok {
		cs10 = removeCEFEscapeChars(cs10)
		var cs10JSON interface{}
		if err := json.Unmarshal([]byte(cs10), &cs10JSON); err == nil {
			ie.CS10 = cs10JSON
		} else {
			ie.CS10 = cs10
		}
	}

	if cs11, ok := fields["cs11"]; ok {
		cs11 = removeCEFEscapeChars(cs11)
		var cs11JSON interface{}
		if err := json.Unmarshal([]byte(cs11), &cs11JSON); err == nil {
			ie.CS11 = cs11JSON
		} else {
			ie.CS11 = cs11
		}
	}

	return fields
}

// GetField dynamically retrieves a field value by name using reflection.
func (ie *ImpervaExtensions) GetField(fieldName string) (interface{}, error) {
	r := reflect.ValueOf(ie)
	f := reflect.Indirect(r).FieldByName(fieldName)
	if f.IsValid() {
		return f.Interface(), nil
	}
	return nil, fmt.Errorf("field %s not found", fieldName)
}

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
	regex := regexp.MustCompile(`^CEF:([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|([^\|]*)\|(.*)$`)
	matches := regex.FindStringSubmatch(cef)

	if len(matches) == 0 {
		return nil, fmt.Errorf("invalid CEF format")
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

// AsJSON returns the CEF event as a pretty JSON string.
func (cef *CEF) AsJSON() string {
	data, _ := json.MarshalIndent(cef, "", "  ")
	return string(data)
}

// AsJSON returns the extension fields as a pretty JSON string.
func (de *DefaultExtensions) AsJSON() string {
	data, _ := json.MarshalIndent(de.Fields, "", "  ")
	return string(data)
}

// AsJSON returns the extension fields as a pretty JSON string.
func (ie *ImpervaExtensions) AsJSON() string {
	data, _ := json.MarshalIndent(ie, "", "  ")
	return string(data)
}

// AsJSON returns the extension fields as a pretty JSON string.
func (ce *CentrifyExtensions) AsJSON() string {
	data, _ := json.MarshalIndent(ce, "", "  ")
	return string(data)
}

// AsMap returns the extension fields as a map.
func (de *DefaultExtensions) AsMap() map[string]string {
	return de.Fields
}

// AsMap returns the extension fields as a map.
func (ie *ImpervaExtensions) AsMap() map[string]string {
	return structToMap(ie)
}

// AsMap returns the extension fields as a map.
func (ce *CentrifyExtensions) AsMap() map[string]string {
	return structToMap(ce)
}

// GetFieldNames returns the field names of the extension.
func (de *DefaultExtensions) GetFieldNames() []string {
	fieldNames := make([]string, 0, len(de.Fields))
	for k := range de.Fields {
		fieldNames = append(fieldNames, k)
	}
	return fieldNames
}

// GetFieldNames returns the field names of the extension.
func (ie *ImpervaExtensions) GetFieldNames() []string {
	return getFieldNames(ie)
}

// GetFieldNames returns the field names of the extension.
func (ce *CentrifyExtensions) GetFieldNames() []string {
	return getFieldNames(ce)
}
