// Tests for the parser package.
package parser

import (
	"reflect"
	"testing"
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
