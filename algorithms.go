// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package hasher

import (
	"crypto"
	"crypto/md5"  //nolint:gosec // Required to support md5
	"crypto/sha1" //nolint:gosec // Required to support sha1
	"crypto/sha256"
	"hash"

	"golang.org/x/crypto/sha3"

	intoto "github.com/in-toto/attestation/go/v1"
)

// HasherFactoryMap is a map that can create hash.Hash objects for
// all the recognized algorithm types.
type HasherFactoryMap map[intoto.HashAlgorithm]func() hash.Hash

func (hf *HasherFactoryMap) GetHasher(algo intoto.HashAlgorithm) hash.Hash {
	if _, ok := (*hf)[algo]; ok {
		return (*hf)[algo]()
	}
	return nil
}

// HasherFactory is a preconfigured hasher map with all the known
// algorithm types
var HasherFactory = HasherFactoryMap{
	intoto.AlgorithmMD5:        md5.New,
	intoto.AlgorithmSHA1:       sha1.New,
	intoto.AlgorithmSHA224:     crypto.SHA224.New,
	intoto.AlgorithmSHA512_224: crypto.SHA512_224.New,
	intoto.AlgorithmSHA256:     sha256.New,
	intoto.AlgorithmSHA512_256: crypto.SHA512_256.New,
	intoto.AlgorithmSHA384:     crypto.SHA384.New,
	intoto.AlgorithmSHA512:     crypto.SHA512.New,
	intoto.AlgorithmSHA3_224:   crypto.SHA3_224.New,
	intoto.AlgorithmSHA3_256:   crypto.SHA3_256.New,
	intoto.AlgorithmSHA3_384:   crypto.SHA384.New,
	intoto.AlgorithmSHA3_512:   sha3.New512,
	intoto.AlgorithmGitBlob:    sha1.New,
	intoto.AlgorithmGitCommit:  sha1.New,
	intoto.AlgorithmGitTag:     sha1.New,
	intoto.AlgorithmGitTree:    sha1.New,
	intoto.AlgorithmDirHash:    sha1.New,
}
