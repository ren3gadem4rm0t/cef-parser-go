// Package parser provides functionality for parsing CEF events.
package parser

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

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

// AsJSON returns the extension fields as a pretty JSON string.
func (ie *ImpervaExtensions) AsJSON() string {
	data, _ := json.MarshalIndent(ie, "", "  ")
	return string(data)
}

// AsMap returns the extension fields as a map.
func (ie *ImpervaExtensions) AsMap() map[string]string {
	return structToMap(ie)
}

// GetFieldNames returns the field names of the extension.
func (ie *ImpervaExtensions) GetFieldNames() []string {
	return getFieldNames(ie)
}
