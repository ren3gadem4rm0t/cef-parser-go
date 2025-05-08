[![CI](https://github.com/ren3gadem4rm0t/cef-parser-go/actions/workflows/ci.yml/badge.svg)](https://github.com/ren3gadem4rm0t/cef-parser-go/actions/workflows/ci.yml)

# CEF Parser for Go

## Overview

A Go library for parsing Common Event Format (CEF) logs with examples and utilities.

## Features

- Parse CEF logs from multiple vendors
- Retrieve and manipulate CEF fields
- Context-aware CEF parsing with timeout support
- JSON representation of parsed CEF events
- Map conversion of CEF extension fields
- Dynamic field retrieval by name
- Support for custom vendor-specific extensions
- Error handling and validation for CEF formats
- Multiple parser implementations optimized for different use cases
- Configurable validation levels and memory management
- Batch and stream processing capabilities
- Metrics collection for performance monitoring
- Utility functions for struct manipulation
- Examples for basic usage, field access, and field enumeration
- Comprehensive test coverage

## Installation

```bash
go get github.com/ren3gadem4rm0t/cef-parser-go
```

## Usage

### Basic Usage

```go
package main

import (
    "fmt"
    "log"
    "github.com/ren3gadem4rm0t/cef-parser-go/parser"
)

func main() {
    event := parser.ImpervaCEF1
    cefEvent, err := parser.ParseCEF(event)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(cefEvent.AsJSON())
}
```

### Field Access

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"
    "github.com/ren3gadem4rm0t/cef-parser-go/parser"
)

func main() {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    event := parser.ImpervaCEF1
    cefEvent, err := parser.ParseCEFWithContext(ctx, event)
    if err != nil {
        log.Fatal(err)
    }

    cs10, err := cefEvent.Extensions.GetField("CS10")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("CS10: %+v\n", cs10)
}
```

### Configure Parser Behavior

```go
package main

import (
    "fmt"
    "log"
    "github.com/ren3gadem4rm0t/cef-parser-go/parser"
)

func main() {
    // Create a parser with fast configuration
    fastParser := parser.NewParser(parser.FastConfig())
    
    event := parser.ImpervaCEF1
    cefEvent, err := fastParser.Parse(event)
    if err != nil {
        log.Fatal(err)
    }
    
    // Return object to pool when done
    defer fastParser.Release(cefEvent)
    
    fmt.Printf("Parsed %s | %s\n", cefEvent.DeviceVendor, cefEvent.Name)
    
    // Get parser metrics
    metrics := fastParser.GetMetrics()
    fmt.Printf("Parsed %d events, %d bytes processed\n", 
        metrics[parser.MetricParsed], 
        metrics[parser.MetricBytesProcessed])
}
```

### Batch Processing for High Throughput

```go
package main

import (
    "fmt"
    "log"
    "github.com/ren3gadem4rm0t/cef-parser-go/parser"
)

func main() {
    events := []string{
        parser.ImpervaCEF1,
        parser.ImpervaCEF5,
        parser.CentrifyCEF,
    }
    
    // Create a fast parser for high performance
    fastParser := parser.NewParser(parser.FastConfig())
    
    // Process multiple events in parallel
    results, errors := fastParser.BatchParse(events)
    
    for i, result := range results {
        if errors[i] != nil {
            fmt.Printf("Error parsing event %d: %v\n", i, errors[i])
        } else {
            fmt.Printf("Event %d: %s %s\n", i, result.DeviceVendor, result.Name)
            
            // Return object to pool
            fastParser.Release(result)
        }
    }
}
```

### Stream Processing

```go
package main

import (
    "bufio"
    "fmt"
    "log"
    "os"
    "github.com/ren3gadem4rm0t/cef-parser-go/parser"
)

func main() {
    // Open a file with CEF events
    file, err := os.Open("events.log")
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()
    
    // Create a parser with safe configuration for robust validation
    safeParser := parser.NewParser(parser.SafeConfig())
    
    // Process events from a stream
    err = safeParser.ParseStream(file, func(cef *parser.CEF, err error) bool {
        if err != nil {
            fmt.Printf("Error: %v\n", err)
            return true // continue processing
        }
        
        fmt.Printf("Parsed: %s | %s\n", cef.DeviceVendor, cef.Name)
        safeParser.Release(cef)
        return true // continue processing
    })
    
    if err != nil {
        log.Fatal(err)
    }
}
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for more details.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.
