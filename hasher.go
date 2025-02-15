// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package hasher

import (
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sync"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/nozzle/throttler"
)

// maxOpenFiles limits the maximum number of files we'll open
// to avoid resource exhaustion
var maxOpenFiles = 1024

// New returns a new Hasher configured with the default options
func New() *Hasher {
	return &Hasher{
		Options: defaultOptions,
	}
}

// Hasher is an object that has methods to hash data.
type Hasher struct {
	Options Options
}

type (
	// HashSet captures a set of hashes of the same artifact.
	HashSet map[intoto.HashAlgorithm]string

	// FileHashSet captures a set of hashes of the same artifact
	// indexed by its path.
	FileHashSet map[string]HashSet

	// HashSetList is an array of HashSets.
	HashSetList []HashSet
)

func closeFiles(readers []io.Reader) {
	for _, r := range readers {
		if r == nil {
			continue
		}

		f, ok := r.(*os.File)
		if ok {
			f.Close()
		}
	}
}

// HashFiles gets a list of paths and returns the file hashes indexed
// by path name. The results are guaranteed to be in the same order but
// any repeated paths will be hashed more than once and included only
// once in the returned structure.
func (h *Hasher) HashFiles(paths []string) (*FileHashSet, error) {
	if len(paths) > maxOpenFiles {
		return nil, fmt.Errorf("maximum number of files specified (%d)", maxOpenFiles)
	}

	readers := make([]io.Reader, len(paths))
	defer closeFiles(readers)

	for i, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("opening file")
		}
		readers[i] = f
	}

	// Run the readers throhj the hasher
	hashes, err := h.HashReaders(readers)
	if err != nil {
		return nil, fmt.Errorf("hashing open files: %w", err)
	}

	// Ensure we got the right number of hash sets to avoid
	// a panic if we didn't for some reason:
	if len(*hashes) != len(paths) {
		return nil, fmt.Errorf("unexpected hashes returned from hasher")
	}

	// Assemble the results
	ret := FileHashSet{}
	for i, path := range paths {
		ret[path] = (*hashes)[i]
	}

	return &ret, nil
}

// HashFiles takes a list of files and returns the hashes for them
func (h *Hasher) HashReaders(readers []io.Reader) (*HashSetList, error) {
	ret := make(HashSetList, len(readers))
	errs := []error{}

	var mutex sync.Mutex
	t := throttler.New((4), len(readers))
	for i, r := range readers {
		go func() {
			hashes, err := h.hashReader(r)
			if err != nil {
				errs = append(errs, err)
				return
			}
			mutex.Lock()
			ret[i] = *hashes
			mutex.Unlock()
			t.Done(err)
		}()
		t.Throttle()
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	return &ret, nil
}

// hashReader hashes the data stream read from r into the configured
// algorithms. While IO writing is paralelized, the hash computation is
// done serially as threads are controlled in the calling functions.
func (h *Hasher) hashReader(r io.Reader) (*HashSet, error) {
	if len(h.Options.Algorithms) == 0 {
		return nil, fmt.Errorf("no algorithms configured in hasher")
	}
	ret := HashSet{}
	var mutex sync.Mutex
	writers := []io.Writer{}

	for _, algo := range h.Options.Algorithms {
		cryptoHasher := HasherFactory.GetHasher(algo)
		if cryptoHasher == nil {
			return nil, fmt.Errorf("no hasher found for %q", algo)
		}

		writers = append(writers, cryptoHasher)
	}

	mw := io.MultiWriter(writers...)
	if _, err := io.Copy(mw, r); err != nil {
		return nil, fmt.Errorf("copying io stream to crypto hasher")
	}

	for i, w := range writers {
		mutex.Lock()
		ret[h.Options.Algorithms[i]] = fmt.Sprintf("%x", w.(hash.Hash).Sum(nil)) //nolint:errcheck
		mutex.Unlock()
	}

	return &ret, nil
}
