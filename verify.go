// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package hasher

import (
	"fmt"
	"io"

	intoto "github.com/in-toto/attestation/go/v1"
)

// VerifyReader compares a set of hashes against a reader data. If all
// match then it returns true. If a hash mismatches, it returns false.
func (h *Hasher) VerifyReader(r io.Reader, set *HashSet) (bool, error) {
	var algos []intoto.HashAlgorithm
	for a := range *set {
		algos = append(algos, a)
	}
	control, err := h.hashReader(r, WithAlgorithms(algos))
	if err != nil {
		return false, fmt.Errorf("hashing stream: %s", err)
	}

	var errs = []error{}
	for algo := range *control {
		if (*set)[algo] != (*control)[algo] {
			errs = append(errs, fmt.Errorf("%s hash does not match", algo))
			fmt.Printf("%+v\n", errs)
		}
	}

	return len(errs) == 0, nil
}
