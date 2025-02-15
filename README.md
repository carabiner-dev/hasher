# github.com/carabiner-dev/hasher

A simple go module to hash data focused on simplicity, performance and
ease of use.

## Install the Module

To install in your project simply use `go get`:

```
go get github.com/carabiner-dev/hasher
```

## Examples

The hasher object can hash lists of `io.Reader` or a list of file paths:

```golang
package main

import (
    "github.com/carabiner-dev/hasher"
    intoto "github.com/in-toto/attestation/go/v1"
)

// Simple program to compute checksums of files
func main() {
    h := hasher.New()

    // Configure the algorithms hasher will use (optional):
    h.Options.Algorithms = []intoto.HashAlgorithm{
		intoto.AlgorithmSHA256, intoto.AlgorithmSHA512,
	}

    // Configure how many files to hash at once:
    h.Options.MaxParallel = 2

    // Run the hasher:
    hashes, err := h.HashFiles([]string{
        "hello.txt", "README.md",
    })
    if err != nil {
        os.Exit(1)
    }

    // Print the results:
    for path, hs := range hashes {
        fmt.Println(path + ":")
        for algo, value := range hs {
            fmt.Printf("  %s:%s\n", algo, value)
        }
    }
}
```

The resulting types can be natively converted to in-toto Resource
Descriptors to easily use them when building attestations:

```golang
  // Hash a bunch of files:
  hashes, err := h.HashFiles([]string{"hello.txt", "README.md",})

  // Convert to a slice of intoto.ResourceDescriptor:
  descriptors = hashes.ToResourceDescriptors()
```

## Implementation

The hasher implementation runs the hashing processes in parallel. While
the sums for each algorithm are computed serially, hasher handles four 
input streams at the same time by default. 

The list of supported hashes is imported from the 
[hashing algorithms recognized in the in-toto project](https://github.com/in-toto/attestation/blob/main/go/v1/resource_descriptor.go).

Note that the list of paths to hashed is artificially capped at 1024 to
avoid ddos'ing the hasher.

## License

This module is open source, licensed under the Apache 2.0 license
