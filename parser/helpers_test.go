// Tests for the helper functions.
package parser

import (
	"reflect"
	"testing"
)

// TestGetFieldNames tests the getFieldNames function.
func TestGetFieldNames(t *testing.T) {
	type TestStruct struct {
		Field1 string
		Field2 int
		Field3 bool
	}

	obj := &TestStruct{
		Field1: "value1",
		Field2: 42,
		Field3: true,
	}

	expected := []string{"Field1", "Field2", "Field3"}
	fieldNames := getFieldNames(obj)

	if !reflect.DeepEqual(fieldNames, expected) {
		t.Errorf("getFieldNames() = %v, want %v", fieldNames, expected)
	}
}

// TestStructToMap tests the structToMap function.
func TestStructToMap(t *testing.T) {
	type TestStruct struct {
		Field1 string
		Field2 int
		Field3 bool
	}

	obj := &TestStruct{
		Field1: "value1",
		Field2: 42,
		Field3: true,
	}

	expected := map[string]string{
		"field1": "value1",
	}

	fields := structToMap(obj)

	if !reflect.DeepEqual(fields, expected) {
		t.Errorf("structToMap() = %v, want %v", fields, expected)
	}
}
