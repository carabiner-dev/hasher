// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package hasher

import (
	"path/filepath"

	intoto "github.com/in-toto/attestation/go/v1"
)

// ToResourceDescritor()

func (fhs *FileHashSet) ToResourceDescriptors() []*intoto.ResourceDescriptor {
	ret := make([]*intoto.ResourceDescriptor, len(*fhs))
	i := 0
	for path, hs := range *fhs {
		ret[i] = hs.ToResourceDescriptor()
		ret[i].Uri = path
		ret[i].Name = filepath.Base(path)
		i++
	}

	return ret
}

func (hsl *HashSetList) ToResourceDescriptors() []*intoto.ResourceDescriptor {
	ret := make([]*intoto.ResourceDescriptor, len(*hsl))
	for i, hs := range *hsl {
		ret[i] = hs.ToResourceDescriptor()
	}

	return ret
}

func (hs *HashSet) ToResourceDescriptor() *intoto.ResourceDescriptor {
	resdes := &intoto.ResourceDescriptor{
		Digest: map[string]string{},
	}

	for algo, val := range *hs {
		resdes.Digest[string(algo)] = val
	}

	return resdes
}
