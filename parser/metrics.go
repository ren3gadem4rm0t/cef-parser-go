// Package parser provides functionality for parsing CEF events.
package parser

// Metrics constants
const (
	// MetricParsed counts successfully parsed events
	MetricParsed = "parsed"

	// MetricErrors counts parsing errors
	MetricErrors = "errors"

	// MetricValidationErrs counts validation errors
	MetricValidationErrs = "validation_errors"

	// MetricBytesProcessed counts total bytes processed
	MetricBytesProcessed = "bytes_processed"

	// MetricObjectsReleased counts objects returned to the pool
	MetricObjectsReleased = "objects_released"

	// MetricPoolHits counts object pool hits
	MetricPoolHits = "pool_hits"

	// MetricPoolMisses counts object pool misses
	MetricPoolMisses = "pool_misses"

	// MetricJSONFixed counts fixed JSON values
	MetricJSONFixed = "json_fixed"
)
