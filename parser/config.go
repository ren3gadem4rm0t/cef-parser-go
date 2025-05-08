// Package parser provides functionality for parsing CEF events.
package parser

// ParserMode defines the type of parser to use
type ParserMode int

const (
	// ModeAuto automatically selects the best parser based on the scenario
	ModeAuto ParserMode = iota

	// ModeStandard uses the standard parser with regex and better error messages
	ModeStandard

	// ModeFast uses the faster parser with optimized performance and lower allocations
	ModeFast

	// ModeSafe uses the standard parser with extra validation checks
	ModeSafe
)

// ValidationLevel controls how strict the parser is with validation
type ValidationLevel int

const (
	// ValidationFull performs all validation checks
	ValidationFull ValidationLevel = iota

	// ValidationBasic performs only basic structure validation
	ValidationBasic

	// ValidationMinimal performs minimal validation for maximum performance
	ValidationMinimal
)

// ParserConfig holds configuration options for CEF parsing
type ParserConfig struct {
	// Mode selects which parser implementation to use
	Mode ParserMode

	// Validation controls the validation level
	Validation ValidationLevel

	// UsePooling enables object pooling for better performance
	UsePooling bool

	// MaxEventSize sets the maximum size of CEF events in bytes
	MaxEventSize int

	// EnableMetrics enables collection of parsing metrics
	EnableMetrics bool

	// EnableThreadSafePooling uses thread-local storage for object pools
	EnableThreadSafePooling bool

	// EnableDiagnostics enables more detailed error messages
	EnableDiagnostics bool
}

// DefaultConfig returns the default parser configuration
func DefaultConfig() ParserConfig {
	return ParserConfig{
		Mode:                    ModeAuto,
		Validation:              ValidationBasic,
		UsePooling:              true,
		MaxEventSize:            20000,
		EnableMetrics:           false,
		EnableThreadSafePooling: false,
		EnableDiagnostics:       false,
	}
}

// SafeConfig returns a configuration optimized for correctness over performance
func SafeConfig() ParserConfig {
	return ParserConfig{
		Mode:                    ModeSafe,
		Validation:              ValidationFull,
		UsePooling:              false,
		MaxEventSize:            10000,
		EnableMetrics:           false,
		EnableThreadSafePooling: false,
		EnableDiagnostics:       true,
	}
}

// FastConfig returns a configuration optimized for maximum performance
func FastConfig() ParserConfig {
	return ParserConfig{
		Mode:                    ModeFast,
		Validation:              ValidationMinimal,
		UsePooling:              true,
		MaxEventSize:            20000,
		EnableMetrics:           true,
		EnableThreadSafePooling: true,
		EnableDiagnostics:       false,
	}
}
