// Tests for the parser package.
package parser

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// TestParseImpervaCEFWithQuotes tests the parsing of Imperva CEF with quotes.
func TestParseImpervaCEFWithQuotes(t *testing.T) {
	cefEvent, err := ParseCEF(ImpervaCEF1)
	if err != nil {
		t.Fatalf("ParseCEF() error = %v", err)
	}

	expected := &CEF{
		Version:       "0",
		DeviceVendor:  "Incapsula",
		DeviceProduct: "SIEMintegration",
		DeviceVersion: "1",
		SignatureID:   "1",
		Name:          "Normal",
		Severity:      "0",
		Extensions: &ImpervaExtensions{
			FileID:                   "1234567890123456789",
			SourceServiceName:        "example.com",
			SiteID:                   "1234567",
			SUID:                     "123456",
			RequestClientApplication: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.0.0 Safari/537.36 Edg/99.0.0.0",
			DeviceFacility:           "abc",
			CS2:                      "true",
			CS2Label:                 "Javascript Support",
			CS3:                      "true",
			CS3Label:                 "CO Support",
			CS1:                      "NA",
			CS1Label:                 "Cap Support",
			CS4:                      "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			CS4Label:                 "VID",
			CS5:                      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			CS5Label:                 "clappsig",
			DProc:                    "Browser",
			CS6:                      "Microsoft Edge",
			CS6Label:                 "clapp",
			CCCode:                   "US",
			CS7:                      "37.751",
			CS7Label:                 "latitude",
			CS8:                      "-97.822",
			CS8Label:                 "longitude",
			Customer:                 "ExampleCustomer",
			Start:                    "1720396716929",
			Request:                  "example.com/path/to/resource",
			Ref:                      "https://example.com/path/to/referrer",
			RequestMethod:            "GET",
			CN1:                      "200",
			App:                      "HTTPS",
			Act:                      "REQ_CACHED_VALIDATED",
			DeviceExternalID:         "12345678901234567",
			SIP:                      "123.123.123.123",
			SPT:                      "443",
			In:                       "451",
			XFF: []string{
				"123.123.123.123",
			},
			CS10: []interface{}{
				map[string]interface{}{
					"rule_id":        "1234567",
					"type":           "AD_HEADER_RW",
					"header_name":    "Content-Security-Policy",
					"header_rewrite": "frame-ancestors 'self' https://example.com http://example.com https://test.2example.com https://test1.example.com https://test0.example.com",
				},
				map[string]interface{}{
					"rule_id":        "1234567",
					"type":           "AD_HEADER_RW",
					"header_name":    "X-Content-Type-Options",
					"header_rewrite": "nosniff",
				},
				map[string]interface{}{
					"rule_id":        "1234567",
					"type":           "AD_HEADER_RW",
					"header_name":    "Referrer-Policy",
					"header_rewrite": "strict-origin-when-cross-origin",
				},
				map[string]interface{}{
					"rule_id":        "1234567",
					"type":           "AD_HEADER_RW",
					"header_name":    "X-XSS-Protection",
					"header_rewrite": "1; mode=block",
				},
				map[string]interface{}{
					"rule_id":        "1234567",
					"type":           "AD_HEADER_RW",
					"header_name":    "X-Frame-Options",
					"header_rewrite": "ALLOW FROM https://example.com http://example.com https://test.2example.com https://test1.example.com https://test0.example.com",
				},
				map[string]interface{}{
					"rule_id":        "1234567",
					"type":           "AD_HEADER_RW",
					"header_name":    "Expect-CT",
					"header_rewrite": "max-age=86400, enforce",
				},
				map[string]interface{}{
					"rule_id":        "1234567",
					"type":           "AD_HEADER_RW",
					"header_name":    "Host",
					"header_orig":    "example.com",
					"header_rewrite": "www.example.com",
				},
				map[string]interface{}{
					"rule_id":          "1234567",
					"type":             "AD_FORWARD_TO_DC",
					"forward_to_dc_id": "1234567",
				},
			},
			CS10Label: "Rule Info",
			CS11:      "",
			CS11Label: "",
			CPT:       "10401",
			Src:       "123.123.123.123",
			Ver:       "TLSv1.3 TLS_AES_128_GCM_SHA256",
			End:       "1720396717135",
		},
	}

	if !reflect.DeepEqual(cefEvent, expected) {
		t.Errorf("ParseCEF() = %v, want %v", cefEvent, expected)
		compareStructs(cefEvent, expected, t)
	}

	// Test GetField method
	cs10, err := cefEvent.Extensions.GetField("CS10")
	if err != nil {
		t.Fatalf("GetField() error = %v", err)
	}
	if !reflect.DeepEqual(cs10, expected.Extensions.(*ImpervaExtensions).CS10) {
		t.Errorf("GetField(CS10) = %v, want %v", cs10, expected.Extensions.(*ImpervaExtensions).CS10)
	}
}

// TestParseImpervaCEFWithoutQuotes tests the parsing of Imperva CEF without quotes.
func TestParseImpervaCEFWithoutQuotes(t *testing.T) {
	cefEvent, err := ParseCEF(ImpervaCEF2)
	if err != nil {
		t.Fatalf("ParseCEF() error = %v", err)
	}

	expected := &CEF{
		Version:       "0",
		DeviceVendor:  "Incapsula",
		DeviceProduct: "SIEMintegration",
		DeviceVersion: "1",
		SignatureID:   "1",
		Name:          "Normal",
		Severity:      "0",
		Extensions: &ImpervaExtensions{
			FileID:                   "1234567890123456789",
			SourceServiceName:        "example.com",
			SiteID:                   "1234567",
			SUID:                     "123456",
			RequestClientApplication: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.0.0 Safari/537.36 Edg/99.0.0.0",
			DeviceFacility:           "abc",
			CS2:                      "true",
			CS2Label:                 "Javascript Support",
			CS3:                      "true",
			CS3Label:                 "CO Support",
			CS1:                      "NA",
			CS1Label:                 "Cap Support",
			CS4:                      "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			CS4Label:                 "VID",
			CS5:                      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			CS5Label:                 "clappsig",
			DProc:                    "Browser",
			CS6:                      "Microsoft Edge",
			CS6Label:                 "clapp",
			CCCode:                   "US",
			CS7:                      "37.751",
			CS7Label:                 "latitude",
			CS8:                      "-97.822",
			CS8Label:                 "longitude",
			Customer:                 "ExampleCustomer",
			Start:                    "1720396716929",
			Request:                  "example.com/path/to/resource",
			Ref:                      "https://example.com/path/to/referrer",
			RequestMethod:            "GET",
			CN1:                      "200",
			App:                      "HTTPS",
			Act:                      "REQ_CACHED_VALIDATED",
			DeviceExternalID:         "12345678901234567",
			SIP:                      "123.123.123.123",
			SPT:                      "443",
			In:                       "451",
			XFF: []string{
				"123.123.123.123",
			},
			CS10: []interface{}{
				map[string]interface{}{
					"rule_id":        "1234567",
					"type":           "AD_HEADER_RW",
					"header_name":    "Content-Security-Policy",
					"header_rewrite": "frame-ancestors 'self' https://example.com http://example.com https://test.2example.com https://test1.example.com https://test0.example.com",
				},
				map[string]interface{}{
					"rule_id":        "1234567",
					"type":           "AD_HEADER_RW",
					"header_name":    "X-Content-Type-Options",
					"header_rewrite": "nosniff",
				},
				map[string]interface{}{
					"rule_id":        "1234567",
					"type":           "AD_HEADER_RW",
					"header_name":    "Referrer-Policy",
					"header_rewrite": "strict-origin-when-cross-origin",
				},
				map[string]interface{}{
					"rule_id":        "1234567",
					"type":           "AD_HEADER_RW",
					"header_name":    "X-XSS-Protection",
					"header_rewrite": "1; mode=block",
				},
				map[string]interface{}{
					"rule_id":        "1234567",
					"type":           "AD_HEADER_RW",
					"header_name":    "X-Frame-Options",
					"header_rewrite": "ALLOW FROM https://example.com http://example.com https://test.2example.com https://test1.example.com https://test0.example.com",
				},
				map[string]interface{}{
					"rule_id":        "1234567",
					"type":           "AD_HEADER_RW",
					"header_name":    "Expect-CT",
					"header_rewrite": "max-age=86400, enforce",
				},
				map[string]interface{}{
					"rule_id":        "1234567",
					"type":           "AD_HEADER_RW",
					"header_name":    "Host",
					"header_orig":    "example.com",
					"header_rewrite": "www.example.com",
				},
				map[string]interface{}{
					"rule_id":          "1234567",
					"type":             "AD_FORWARD_TO_DC",
					"forward_to_dc_id": "1234567",
				},
			},
			CS10Label: "Rule Info",
			CS11:      "",
			CS11Label: "",
			CPT:       "10401",
			Src:       "123.123.123.123",
			Ver:       "TLSv1.3 TLS_AES_128_GCM_SHA256",
			End:       "1720396717135",
		},
	}

	if !reflect.DeepEqual(cefEvent, expected) {
		t.Errorf("ParseCEF() = %v, want %v", cefEvent, expected)
		compareStructs(cefEvent, expected, t)
	}

	// Test GetField method
	cs10, err := cefEvent.Extensions.GetField("CS10")
	if err != nil {
		t.Fatalf("GetField() error = %v", err)
	}
	if !reflect.DeepEqual(cs10, expected.Extensions.(*ImpervaExtensions).CS10) {
		t.Errorf("GetField(CS10) = %v, want %v", cs10, expected.Extensions.(*ImpervaExtensions).CS10)
	}
}

// TestParseImpervaCEFWithXFFList tests the parsing of Imperva CEF with a list of XFF values.
func TestParseImpervaCEFWithXFFList(t *testing.T) {
	cefEvent, err := ParseCEF(ImpervaCEF3)
	if err != nil {
		t.Fatalf("ParseCEF() error = %v", err)
	}

	expected := &CEF{
		Version:       "0",
		DeviceVendor:  "Incapsula",
		DeviceProduct: "SIEMintegration",
		DeviceVersion: "1",
		SignatureID:   "1",
		Name:          "Normal",
		Severity:      "0",
		Extensions: &ImpervaExtensions{
			FileID:                   "1234567890123456789",
			SourceServiceName:        "example.com",
			SiteID:                   "1234567",
			SUID:                     "123456",
			RequestClientApplication: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.0.0 Safari/537.36 Edg/99.0.0.0",
			DeviceFacility:           "abc",
			CS2:                      "true",
			CS2Label:                 "Javascript Support",
			CS3:                      "true",
			CS3Label:                 "CO Support",
			CS1:                      "NA",
			CS1Label:                 "Cap Support",
			CS4:                      "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			CS4Label:                 "VID",
			CS5:                      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			CS5Label:                 "clappsig",
			DProc:                    "Browser",
			CS6:                      "Microsoft Edge",
			CS6Label:                 "clapp",
			CCCode:                   "US",
			CS7:                      "37.751",
			CS7Label:                 "latitude",
			CS8:                      "-97.822",
			CS8Label:                 "longitude",
			Customer:                 "ExampleCustomer",
			Start:                    "1720396716929",
			Request:                  "example.com/path/to/resource",
			Ref:                      "https://example.com/path/to/referrer",
			RequestMethod:            "GET",
			CN1:                      "200",
			App:                      "HTTPS",
			Act:                      "REQ_CACHED_VALIDATED",
			DeviceExternalID:         "12345678901234567",
			SIP:                      "123.123.123.123",
			SPT:                      "443",
			In:                       "451",
			XFF: []string{
				"10.1.1.1",
				"123.123.123.123",
			},
			CS10: []interface{}{
				map[string]interface{}{
					"rule_id":        "1234567",
					"type":           "AD_HEADER_RW",
					"header_name":    "Content-Security-Policy",
					"header_rewrite": "frame-ancestors 'self' https://example.com http://example.com https://test.2example.com https://test1.example.com https://test0.example.com",
				},
				map[string]interface{}{
					"rule_id":        "1234567",
					"type":           "AD_HEADER_RW",
					"header_name":    "X-Content-Type-Options",
					"header_rewrite": "nosniff",
				},
				map[string]interface{}{
					"rule_id":        "1234567",
					"type":           "AD_HEADER_RW",
					"header_name":    "Referrer-Policy",
					"header_rewrite": "strict-origin-when-cross-origin",
				},
				map[string]interface{}{
					"rule_id":        "1234567",
					"type":           "AD_HEADER_RW",
					"header_name":    "X-XSS-Protection",
					"header_rewrite": "1; mode=block",
				},
				map[string]interface{}{
					"rule_id":        "1234567",
					"type":           "AD_HEADER_RW",
					"header_name":    "X-Frame-Options",
					"header_rewrite": "ALLOW FROM https://example.com http://example.com https://test.2example.com https://test1.example.com https://test0.example.com",
				},
				map[string]interface{}{
					"rule_id":        "1234567",
					"type":           "AD_HEADER_RW",
					"header_name":    "Expect-CT",
					"header_rewrite": "max-age=86400, enforce",
				},
				map[string]interface{}{
					"rule_id":        "1234567",
					"type":           "AD_HEADER_RW",
					"header_name":    "Host",
					"header_orig":    "example.com",
					"header_rewrite": "www.example.com",
				},
				map[string]interface{}{
					"rule_id":          "1234567",
					"type":             "AD_FORWARD_TO_DC",
					"forward_to_dc_id": "1234567",
				},
			},
			CS10Label: "Rule Info",
			CPT:       "10401",
			CS11Label: "",
			CS11:      "",
			Src:       "123.123.123.123",
			Ver:       "TLSv1.3 TLS_AES_128_GCM_SHA256",
			End:       "1720396717135",
		},
	}

	if !reflect.DeepEqual(cefEvent, expected) {
		t.Errorf("ParseCEF() = %v, want %v", cefEvent, expected)
		compareStructs(cefEvent, expected, t)
	}

	// Test GetField method
	cs10, err := cefEvent.Extensions.GetField("CS10")
	if err != nil {
		t.Fatalf("GetField() error = %v", err)
	}
	if !reflect.DeepEqual(cs10, expected.Extensions.(*ImpervaExtensions).CS10) {
		t.Errorf("GetField(CS10) = %v, want %v", cs10, expected.Extensions.(*ImpervaExtensions).CS10)
	}
}

// TestParseCentrifyCEF tests the parsing of Centrify CEF.
func TestParseCentrifyCEF(t *testing.T) {
	cefEvent, err := ParseCEF(CentrifyCEF)
	if err != nil {
		t.Fatalf("ParseCEF() error = %v", err)
	}

	expected := &CEF{
		Version:       "0",
		DeviceVendor:  "Centrify",
		DeviceProduct: "Centrify_Cloud",
		DeviceVersion: "1.0",
		SignatureID:   "Cloud.Saas.Application",
		Name:          "Cloud.Saas.Application.SelfServiceAppLaunch",
		Severity:      "5",
		Extensions: &CentrifyExtensions{
			DHost:              "AAA0056",
			DUser:              "cloudadmin@persistent.com01",
			Msg:                "User cloudadmin@persistent.com01 launched Instagram from 103.6.32.100",
			SHost:              "103.6.32.100",
			Src:                "103.6.32.100",
			RT:                 "1525844566655",
			DeviceProcessName:  "centrify-syslog-writer",
			DvcHost:            "dinesh-VirtualBox",
			DTZ:                "Africa/Abidjan",
			RequestContext:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36 Edge/15.15063",
			ExternalID:         "772a4a904e82da87.W00.0315.1aa20afe647f09c",
			DPriv:              "WebRole",
			DestinationService: "CDS",
			SUID:               "c2c7bcc6-9560-44e0-8dff-5be221cd37ee",
			CS1:                "Instagram",
			CS1Label:           "applicationId",
			CS2:                "Instagram",
			CS2Label:           "applicationName",
			CS3:                "Web",
			CS3Label:           "applicationType",
			CS4:                "103.6.32.100",
			CS4Label:           "clientIPAddress",
			CS5:                "65f79bb1-4f91-4496-9991-d148da16cc3e",
			CS5Label:           "internalSessionId",
			CS6:                "0d10a24f4c57434198fb3ad4559cc48b",
			CS6Label:           "azDeploymentId",
		},
	}

	if !reflect.DeepEqual(cefEvent, expected) {
		t.Errorf("ParseCEF() = %v, want %v", cefEvent, expected)
		compareStructs(cefEvent, expected, t)
	}

	// Test GetField method
	cs10, err := cefEvent.Extensions.GetField("CS10")
	if err == nil {
		t.Fatalf("GetField() expected error, got nil")
	}
	if cs10 != nil {
		t.Errorf("GetField(CS10) = %v, want nil", cs10)
	}
}

// compareStructs compares the fields of two CEF structs.
func compareStructs(actual, expected *CEF, t *testing.T) {
	valActual := reflect.ValueOf(actual).Elem()
	valExpected := reflect.ValueOf(expected).Elem()
	typeOfActual := valActual.Type()

	for i := 0; i < valActual.NumField(); i++ {
		fieldActual := valActual.Field(i)
		fieldExpected := valExpected.Field(i)
		if !reflect.DeepEqual(fieldActual.Interface(), fieldExpected.Interface()) {
			t.Logf("Field %s: actual = %v, expected = %v", typeOfActual.Field(i).Name, fieldActual.Interface(), fieldExpected.Interface())
		}
	}

	compareExtensions(actual.Extensions, expected.Extensions, t)
}

// compareExtensions compares the fields of two Extensions structs.
func compareExtensions(actual, expected Extensions, t *testing.T) {
	if reflect.TypeOf(actual) != reflect.TypeOf(expected) {
		t.Logf("Extensions type mismatch: actual = %T, expected = %T", actual, expected)
		return
	}

	valActual := reflect.ValueOf(actual).Elem()
	valExpected := reflect.ValueOf(expected).Elem()
	typeOfActual := valActual.Type()

	for i := 0; i < valActual.NumField(); i++ {
		fieldActual := valActual.Field(i)
		fieldExpected := valExpected.Field(i)
		if !reflect.DeepEqual(fieldActual.Interface(), fieldExpected.Interface()) {
			t.Logf("Extension Field %s: actual = %v, expected = %v", typeOfActual.Field(i).Name, fieldActual.Interface(), fieldExpected.Interface())
		}
	}
}

func TestParseCEFWithContext(t *testing.T) {
	tests := []struct {
		name       string
		cef        string
		expectErr  bool
		errMessage string
	}{
		{
			name:      "Valid CEF String",
			cef:       "CEF:0|Incapsula|SIEMintegration|1|1|Normal|0| key1=value1 key2=value2",
			expectErr: false,
		},
		{
			name:       "Invalid CEF Length",
			cef:        "", // Empty string to test length validation
			expectErr:  true,
			errMessage: "invalid CEF string length",
		},
		{
			name:       "Invalid CEF Format",
			cef:        "InvalidCEFString", // Does not match CEF pattern
			expectErr:  true,
			errMessage: "invalid CEF format",
		},
		{
			name:       "Invalid CEF Components",
			cef:        "CEF:0|@InvalidVendor|SIEMintegration|1|1|Normal|0| key1=value1 key2=value2", // Invalid vendor component
			expectErr:  true,
			errMessage: "one or more CEF components are invalid",
		},
		{
			name:      "Valid CEF with Extensions",
			cef:       "CEF:0|Incapsula|SIEMintegration|1|1|Normal|0| key1=value1 key2=value2",
			expectErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()

			cefEvent, err := ParseCEFWithContext(ctx, test.cef)

			if test.expectErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				} else if err.Error() != test.errMessage {
					t.Errorf("expected error message '%s', got '%s'", test.errMessage, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("did not expect error, got '%s'", err.Error())
				} else {
					// Validate the returned CEF event (additional checks can be added here)
					if cefEvent.Version != "0" || cefEvent.DeviceVendor != "Incapsula" {
						t.Errorf("parsed CEF event is incorrect, got %+v", cefEvent)
					}
				}
			}
		})
	}
}

func TestParseCEFWithContextTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	_, err := ParseCEFWithContext(ctx, "CEF:0|Incapsula|SIEMintegration|1|1|Normal|0| key1=value1 key2=value2")
	if err == nil {
		t.Errorf("expected context timeout error, got nil")
	}
	if ctx.Err() != context.DeadlineExceeded {
		t.Errorf("expected context deadline exceeded error, got '%v'", ctx.Err())
	}
}

func TestIsValidCEFKey(t *testing.T) {
	tests := []struct {
		key      string
		expected bool
	}{
		{"validKey1", true},
		{"valid_key", true},
		{"invalid key", false}, // contains space
		{"", false},            // empty key
		{"validKeyWith50Chars123456789012345678901234567890", true},
		{"tooLongKeyWithMoreThan50Chars12345678901234567890123456789012345", false}, // more than 50 chars
		{"invalidKey!", false}, // contains special character
	}

	for _, test := range tests {
		result := isValidCEFKey(test.key)
		if result != test.expected {
			t.Errorf("isValidCEFKey(%q) = %v; want %v", test.key, result, test.expected)
		}
	}
}

func TestIsValidCEFValue(t *testing.T) {
	tests := []struct {
		value    string
		expected bool
	}{
		{"validValue", true},
		{"anotherValidValue", true},
		{"", false}, // empty value
		{"valueWithMoreThan1000Chars" + makeLongString(990), false}, // more than 1000 chars
		{"validValueWithSpecialChars_!@#$%^&*", true},               // special characters are allowed
	}

	for _, test := range tests {
		result := isValidCEFValue(test.value)
		if result != test.expected {
			t.Errorf("isValidCEFValue(%q) = %v; want %v", test.value, result, test.expected)
		}
	}
}

func TestImpervaExtensions_ParseExtensions(t *testing.T) {
	extensionStr := `fileId=1234567890123456789 sourceServiceName=example.com siteid=1234567 suid=123456 requestClientApplication="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.0.0 Safari/537.36 Edg/99.0.0.0" deviceFacility=abc cs2=true cs2Label=Javascript Support cs3=true cs3Label=CO Support ccode=US cs7=37.751 cs7Label=latitude cs8=-97.822 cs8Label=longitude Customer=ExampleCustomer start=1720396716929 request=example.com/path/to/resource ref=https://example.com/path/to/referrer requestMethod=GET cn1=200 app=HTTPS act=REQ_CACHED_VALIDATED deviceExternalId=12345678901234567 sip=123.123.123.123 spt=443 in=451 xff=123.123.123.123 cs10=[{"rule_id":"1234567","type":"AD_HEADER_RW","header_name":"Content-Security-Policy","header_rewrite":"frame-ancestors 'self' https://example.com http://example.com https://test.2example.com https://test1.example.com https://test0.example.com"}] cs10Label=Rule Info cpt=10401 src=123.123.123.123 ver=TLSv1.3 TLS_AES_128_GCM_SHA256 end=1720396717135`

	ie := &ImpervaExtensions{}
	fields := ie.ParseExtensions(extensionStr)

	if ie.FileID != "1234567890123456789" {
		t.Errorf("expected FileID to be '1234567890123456789', got '%s'", ie.FileID)
	}
	if ie.SourceServiceName != "example.com" {
		t.Errorf("expected SourceServiceName to be 'example.com', got '%s'", ie.SourceServiceName)
	}
	// Add additional checks for other fields...
	if _, ok := fields["cs10"]; !ok {
		t.Errorf("expected cs10 to be present in fields map")
	}
	if _, ok := fields["cs11"]; ok {
		t.Errorf("expected cs11 to be absent in fields map")
	}
}

func TestImpervaExtensions_GetField(t *testing.T) {
	ie := &ImpervaExtensions{
		FileID:            "1234567890123456789",
		SourceServiceName: "example.com",
	}

	value, err := ie.GetField("FileID")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != "1234567890123456789" {
		t.Errorf("expected FileID to be '1234567890123456789', got '%v'", value)
	}

	_, err = ie.GetField("NonExistentField")
	if err == nil {
		t.Errorf("expected error for non-existent field, got nil")
	}
}

func TestImpervaExtensions_AsJSON(t *testing.T) {
	ie := &ImpervaExtensions{
		FileID: "1234567890123456789",
	}

	jsonStr := ie.AsJSON()
	expectedJSON := `{
  "FileID": "1234567890123456789",
  "SourceServiceName": "",
  "SiteID": "",
  "SUID": "",
  "RequestClientApplication": "",
  "DeviceFacility": "",
  "CS2": "",
  "CS2Label": "",
  "CS3": "",
  "CS3Label": "",
  "CS1": "",
  "CS1Label": "",
  "CS4": "",
  "CS4Label": "",
  "CS5": "",
  "CS5Label": "",
  "DProc": "",
  "CS6": "",
  "CS6Label": "",
  "CCCode": "",
  "CS7": "",
  "CS7Label": "",
  "CS8": "",
  "CS8Label": "",
  "CS9": "",
  "CS9Label": "",
  "AdditionalReqHeaders": null,
  "AdditionalResHeaders": null,
  "Customer": "",
  "Start": "",
  "Request": "",
  "Ref": "",
  "RequestMethod": "",
  "CN1": "",
  "App": "",
  "Act": "",
  "DeviceExternalID": "",
  "SIP": "",
  "SPT": "",
  "In": "",
  "XFF": null,
  "CS10": null,
  "CS10Label": "",
  "CS11": null,
  "CS11Label": "",
  "CPT": "",
  "Src": "",
  "Ver": "",
  "End": ""
}`

	if jsonStr != expectedJSON {
		t.Errorf("expected JSON '%s', got '%s'", expectedJSON, jsonStr)
	}
}

func TestImpervaExtensions_AsMap(t *testing.T) {
	ie := &ImpervaExtensions{
		FileID: "1234567890123456789",
	}

	fieldsMap := ie.AsMap()

	if fieldsMap["fileid"] != "1234567890123456789" {
		t.Errorf("expected 'fileid' in map to be '1234567890123456789', got '%s'", fieldsMap["fileid"])
	}

	expectedFieldCount := 44 // Total number of fields in ImpervaExtensions
	if len(fieldsMap) != expectedFieldCount {
		t.Errorf("expected map length to be %d, got %d", expectedFieldCount, len(fieldsMap))
	}
}

func TestImpervaExtensions_GetFieldNames(t *testing.T) {
	ie := &ImpervaExtensions{}

	fieldNames := ie.GetFieldNames()

	expectedFields := []string{"FileID", "SourceServiceName", "SiteID", "SUID", "RequestClientApplication", "DeviceFacility", "CS2", "CS2Label", "CS3", "CS3Label", "CS1", "CS1Label", "CS4", "CS4Label", "CS5", "CS5Label", "DProc", "CS6", "CS6Label", "CCCode", "CS7", "CS7Label", "CS8", "CS8Label", "CS9", "CS9Label", "AdditionalReqHeaders", "AdditionalResHeaders", "Customer", "Start", "Request", "Ref", "RequestMethod", "CN1", "App", "Act", "DeviceExternalID", "SIP", "SPT", "In", "XFF", "CS10", "CS10Label", "CS11", "CS11Label", "CPT", "Src", "Ver", "End"}

	for _, expectedField := range expectedFields {
		found := false
		for _, fieldName := range fieldNames {
			if fieldName == expectedField {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected field name '%s' not found in field names", expectedField)
		}
	}
}

func TestImpervaExtensions_ParseExtensions_JSONFields(t *testing.T) {
	extensionStr := `additionalResHeaders=[{"Content-Type":"text/html; charset=UTF-8"}] additionalReqHeaders=[{"User-Agent":"Mozilla/5.0"}] cs10=[{"rule_id":"1234567","type":"AD_HEADER_RW","header_name":"Content-Security-Policy"}] cs11=[{"api_specification_violation_type":"INVALID_PARAM_NAME","parameter_name":"somename"}]`

	ie := &ImpervaExtensions{}
	ie.ParseExtensions(extensionStr)

	// Convert expected values to []interface{} for proper comparison
	expectedResHeaders := []interface{}{
		map[string]interface{}{"Content-Type": "text/html; charset=UTF-8"},
	}
	if !reflect.DeepEqual(ie.AdditionalResHeaders, expectedResHeaders) {
		t.Errorf("expected additionalResHeaders to be '%v', got '%v'", expectedResHeaders, ie.AdditionalResHeaders)
	}

	expectedReqHeaders := []interface{}{
		map[string]interface{}{"User-Agent": "Mozilla/5.0"},
	}
	if !reflect.DeepEqual(ie.AdditionalReqHeaders, expectedReqHeaders) {
		t.Errorf("expected additionalReqHeaders to be '%v', got '%v'", expectedReqHeaders, ie.AdditionalReqHeaders)
	}

	expectedCS10 := []interface{}{
		map[string]interface{}{
			"rule_id":     "1234567",
			"type":        "AD_HEADER_RW",
			"header_name": "Content-Security-Policy",
		},
	}
	if !reflect.DeepEqual(ie.CS10, expectedCS10) {
		t.Errorf("expected CS10 to be '%v', got '%v'", expectedCS10, ie.CS10)
	}

	expectedCS11 := []interface{}{
		map[string]interface{}{
			"api_specification_violation_type": "INVALID_PARAM_NAME",
			"parameter_name":                   "somename",
		},
	}
	if !reflect.DeepEqual(ie.CS11, expectedCS11) {
		t.Errorf("expected CS11 to be '%v', got '%v'", expectedCS11, ie.CS11)
	}
}

func TestDefaultExtensions_ParseExtensions(t *testing.T) {
	extensionStr := `key1=value1 key2=value2`

	de := &DefaultExtensions{}
	de.ParseExtensions(extensionStr)

	if len(de.Fields) != 2 {
		t.Errorf("expected 2 fields, got %d", len(de.Fields))
	}

	if de.Fields["key1"] != "value1" {
		t.Errorf("expected 'key1' to be 'value1', got '%s'", de.Fields["key1"])
	}

	if de.Fields["key2"] != "value2" {
		t.Errorf("expected 'key2' to be 'value2', got '%s'", de.Fields["key2"])
	}
}

func TestDefaultExtensions_GetField(t *testing.T) {
	de := &DefaultExtensions{
		Fields: map[string]string{
			"key1": "value1",
			"key2": "value2",
		},
	}

	value, err := de.GetField("key1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != "value1" {
		t.Errorf("expected 'key1' to be 'value1', got '%s'", value)
	}

	_, err = de.GetField("nonExistentKey")
	if err == nil {
		t.Errorf("expected error for non-existent key, got nil")
	}
}

func TestDefaultExtensions_AsJSON(t *testing.T) {
	de := &DefaultExtensions{
		Fields: map[string]string{
			"key1": "value1",
			"key2": "value2",
		},
	}

	jsonStr := de.AsJSON()
	expectedJSON := `{
  "key1": "value1",
  "key2": "value2"
}`

	if jsonStr != expectedJSON {
		t.Errorf("expected JSON '%s', got '%s'", expectedJSON, jsonStr)
	}
}

func TestDefaultExtensions_AsMap(t *testing.T) {
	de := &DefaultExtensions{
		Fields: map[string]string{
			"key1": "value1",
			"key2": "value2",
		},
	}

	fieldsMap := de.AsMap()

	if len(fieldsMap) != 2 {
		t.Errorf("expected map length to be 2, got %d", len(fieldsMap))
	}

	if fieldsMap["key1"] != "value1" {
		t.Errorf("expected 'key1' to be 'value1', got '%s'", fieldsMap["key1"])
	}

	if fieldsMap["key2"] != "value2" {
		t.Errorf("expected 'key2' to be 'value2', got '%s'", fieldsMap["key2"])
	}
}

func TestDefaultExtensions_GetFieldNames(t *testing.T) {
	de := &DefaultExtensions{
		Fields: map[string]string{
			"key1": "value1",
			"key2": "value2",
		},
	}

	fieldNames := de.GetFieldNames()

	expectedFieldNames := []string{"key1", "key2"}

	if !reflect.DeepEqual(fieldNames, expectedFieldNames) {
		t.Errorf("expected field names to be '%v', got '%v'", expectedFieldNames, fieldNames)
	}
}

func TestCentrifyExtensions_ParseExtensions(t *testing.T) {
	extensionStr := `dhost=AAA0056 duser=cloudadmin@persistent.com01 msg="User cloudadmin@persistent.com01 launched Instagram from 103.6.32.100" shost=103.6.32.100 src=103.6.32.100 rt=1525844566655 deviceProcessName=centrify-syslog-writer dvchost=dinesh-VirtualBox dtz=Africa/Abidjan requestContext="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36 Edge/15.15063" externalId=772a4a904e82da87.W00.0315.1aa20afe647f09c dpriv=WebRole destinationServiceName=CDS suid=c2c7bcc6-9560-44e0-8dff-5be221cd37ee cs1=Instagram cs1Label=applicationId cs2=Instagram cs2Label=applicationName cs3=Web cs3Label=applicationType cs4=103.6.32.100 cs4Label=clientIPAddress cs5=65f79bb1-4f91-4496-9991-d148da16cc3e cs5Label=internalSessionId cs6=0d10a24f4c57434198fb3ad4559cc48b cs6Label=azDeploymentId`

	ce := &CentrifyExtensions{}
	ce.ParseExtensions(extensionStr)

	if ce.DHost != "AAA0056" {
		t.Errorf("expected DHost to be 'AAA0056', got '%s'", ce.DHost)
	}
	if ce.DUser != "cloudadmin@persistent.com01" {
		t.Errorf("expected DUser to be 'cloudadmin@persistent.com01', got '%s'", ce.DUser)
	}
	// Add additional checks for other fields...
	if ce.CS6Label != "azDeploymentId" {
		t.Errorf("expected CS6Label to be 'azDeploymentId', got '%s'", ce.CS6Label)
	}
}

func TestCentrifyExtensions_GetField(t *testing.T) {
	ce := &CentrifyExtensions{
		DHost: "AAA0056",
		DUser: "cloudadmin@persistent.com01",
	}

	value, err := ce.GetField("DHost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != "AAA0056" {
		t.Errorf("expected 'DHost' to be 'AAA0056', got '%s'", value)
	}

	_, err = ce.GetField("NonExistentField")
	if err == nil {
		t.Errorf("expected error for non-existent field, got nil")
	}
}

func TestCentrifyExtensions_AsJSON(t *testing.T) {
	ce := &CentrifyExtensions{
		DHost: "AAA0056",
		DUser: "cloudadmin@persistent.com01",
	}

	jsonStr := ce.AsJSON()
	expectedJSON := `{
  "DHost": "AAA0056",
  "DUser": "cloudadmin@persistent.com01",
  "Msg": "",
  "SHost": "",
  "Src": "",
  "RT": "",
  "DeviceProcessName": "",
  "DvcHost": "",
  "DTZ": "",
  "RequestContext": "",
  "ExternalID": "",
  "DPriv": "",
  "DestinationService": "",
  "SUID": "",
  "CS1": "",
  "CS1Label": "",
  "CS2": "",
  "CS2Label": "",
  "CS3": "",
  "CS3Label": "",
  "CS4": "",
  "CS4Label": "",
  "CS5": "",
  "CS5Label": "",
  "CS6": "",
  "CS6Label": ""
}`

	if jsonStr != expectedJSON {
		t.Errorf("expected JSON '%s', got '%s'", expectedJSON, jsonStr)
	}
}

func TestCentrifyExtensions_AsMap(t *testing.T) {
	ce := &CentrifyExtensions{
		DHost: "AAA0056",
		DUser: "cloudadmin@persistent.com01",
	}

	fieldsMap := ce.AsMap()

	if len(fieldsMap) != 26 { // Expecting 26 fields since we're returning all fields
		t.Errorf("expected map length to be 26, got %d", len(fieldsMap))
	}

	if fieldsMap["dhost"] != "AAA0056" {
		t.Errorf("expected 'dhost' to be 'AAA0056', got '%s'", fieldsMap["dhost"])
	}

	if fieldsMap["duser"] != "cloudadmin@persistent.com01" {
		t.Errorf("expected 'duser' to be 'cloudadmin@persistent.com01', got '%s'", fieldsMap["duser"])
	}
}

func TestCentrifyExtensions_GetFieldNames(t *testing.T) {
	ce := &CentrifyExtensions{
		DHost: "AAA0056",
		DUser: "cloudadmin@persistent.com01",
	}

	fieldNames := ce.GetFieldNames()

	expectedFieldNames := []string{"DHost", "DUser", "Msg", "SHost", "Src", "RT", "DeviceProcessName", "DvcHost", "DTZ", "RequestContext", "ExternalID", "DPriv", "DestinationService", "SUID", "CS1", "CS1Label", "CS2", "CS2Label", "CS3", "CS3Label", "CS4", "CS4Label", "CS5", "CS5Label", "CS6", "CS6Label"}

	if !reflect.DeepEqual(fieldNames, expectedFieldNames) {
		t.Errorf("expected field names to be '%v', got '%v'", expectedFieldNames, fieldNames)
	}
}

// Helper function to create a long string for testing
func makeLongString(length int) string {
	str := ""
	for i := 0; i < length; i++ {
		str += "a"
	}
	return str
}
