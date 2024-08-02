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

## Contributing
We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for more details.

## License
This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.