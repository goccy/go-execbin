# go-execbin

[![GoDoc](https://godoc.org/github.com/goccy/go-execbin?status.svg)](https://pkg.go.dev/github.com/goccy/go-execbin?tab=doc)

Analyze the binary outputted by `go build` to get type information etc.

# Synopsis

```go
package main

import (
    "github.com/goccy/go-execbin"
)

func main() {
    file, err := execbin.Open("path/to/binary")
    if err != nil {
        panic(err)
    }
    types, err := file.DefinedInterfaceTypes()
    if err != nil {
        panic(err)
    }
}
```