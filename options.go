// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package hasher

import (
	"fmt"

	intoto "github.com/in-toto/attestation/go/v1"
)

type Options struct {
	Algorithms  []intoto.HashAlgorithm
	MaxParallel int
}

var defaultOptions = Options{
	// Algorithms is the list of configured algorithms. Any
	// hashing operation will include these.
	Algorithms: []intoto.HashAlgorithm{
		intoto.AlgorithmSHA256,
		intoto.AlgorithmSHA512,
	},

	// MaxParallel controls how many hashing processes we run at the
	// same time.
	MaxParallel: 4,
}

type OptFn func(*Options) error

func WithAlgorithms[T ~string](algos []T) OptFn {
	return func(o *Options) error {
		o.Algorithms = []intoto.HashAlgorithm{}
		for _, algoString := range algos {
			if _, ok := HasherFactory[intoto.HashAlgorithm(algoString)]; ok {
				o.Algorithms = append(o.Algorithms, intoto.HashAlgorithm(algoString))
			} else {
				return fmt.Errorf("unknown algorithm %q", algoString)
			}
		}
		return nil
	}
}
