// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package hasher

import (
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/require"
)

func TestHSToResourceDescriptor(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		hs     *HashSet
		expect *intoto.ResourceDescriptor
	}{
		{
			"one",
			&HashSet{intoto.AlgorithmSHA1: "410f93f5360bc4f097fa4f553bfcd709f0f8d230"},
			&intoto.ResourceDescriptor{
				Digest: map[string]string{string(intoto.AlgorithmSHA1): "410f93f5360bc4f097fa4f553bfcd709f0f8d230"},
			},
		},
		{
			"two",
			&HashSet{
				intoto.AlgorithmSHA1:   "410f93f5360bc4f097fa4f553bfcd709f0f8d230",
				intoto.AlgorithmSHA256: "7355804febd9ee8357b737b61ea7ca0f1b3ff5c898bc8f003a00beabba7e91fd",
			},
			&intoto.ResourceDescriptor{
				Digest: map[string]string{
					string(intoto.AlgorithmSHA1):   "410f93f5360bc4f097fa4f553bfcd709f0f8d230",
					string(intoto.AlgorithmSHA256): "7355804febd9ee8357b737b61ea7ca0f1b3ff5c898bc8f003a00beabba7e91fd",
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rd := tc.hs.ToResourceDescriptor()
			require.Len(t, rd.Digest, len(tc.expect.Digest))
			for algo, value := range *tc.hs {
				require.Equal(t, tc.expect.Digest[string(algo)], value)
			}
		})
	}
}

func TestHSLToResourceDescriptors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		hsl    *HashSetList
		expect []*intoto.ResourceDescriptor
	}{
		{
			"one",
			&HashSetList{
				HashSet{intoto.AlgorithmSHA1: "410f93f5360bc4f097fa4f553bfcd709f0f8d230"},
			},
			[]*intoto.ResourceDescriptor{
				{
					Digest: map[string]string{string(intoto.AlgorithmSHA1): "410f93f5360bc4f097fa4f553bfcd709f0f8d230"},
				},
			},
		},
		{
			"two",
			&HashSetList{
				HashSet{intoto.AlgorithmSHA1: "410f93f5360bc4f097fa4f553bfcd709f0f8d230"},
				HashSet{
					intoto.AlgorithmSHA1:   "410f93f5360bc4f097fa4f553bfcd709f0f8d230",
					intoto.AlgorithmSHA256: "7355804febd9ee8357b737b61ea7ca0f1b3ff5c898bc8f003a00beabba7e91fd",
				},
			},
			[]*intoto.ResourceDescriptor{
				{
					Digest: map[string]string{string(intoto.AlgorithmSHA1): "410f93f5360bc4f097fa4f553bfcd709f0f8d230"},
				},
				{
					Digest: map[string]string{
						string(intoto.AlgorithmSHA1):   "410f93f5360bc4f097fa4f553bfcd709f0f8d230",
						string(intoto.AlgorithmSHA256): "7355804febd9ee8357b737b61ea7ca0f1b3ff5c898bc8f003a00beabba7e91fd",
					},
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rds := tc.hsl.ToResourceDescriptors()
			require.Len(t, rds, len(tc.expect))
			for i, set := range *tc.hsl {
				for algo, value := range set {
					require.Equal(t, tc.expect[i].Digest[string(algo)], value)
				}
			}
		})
	}
}

func TestFHSToResourceDescriptors(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		hsl    *FileHashSet
		expect []*intoto.ResourceDescriptor
	}{
		{
			"one",
			&FileHashSet{
				"/home/hello.txt": HashSet{intoto.AlgorithmSHA1: "410f93f5360bc4f097fa4f553bfcd709f0f8d230"},
			},
			[]*intoto.ResourceDescriptor{
				{
					Digest: map[string]string{string(intoto.AlgorithmSHA1): "410f93f5360bc4f097fa4f553bfcd709f0f8d230"},
					Name:   "hello.txt",
					Uri:    "/home/hello.txt",
				},
			},
		},
		{
			"two",
			&FileHashSet{
				"/home/hello.txt": HashSet{intoto.AlgorithmSHA1: "410f93f5360bc4f097fa4f553bfcd709f0f8d230"},
				"/home/bye.txt": HashSet{
					intoto.AlgorithmSHA1:   "410f93f5360bc4f097fa4f553bfcd709f0f8d230",
					intoto.AlgorithmSHA256: "7355804febd9ee8357b737b61ea7ca0f1b3ff5c898bc8f003a00beabba7e91fd",
				},
			},
			[]*intoto.ResourceDescriptor{
				{
					Digest: map[string]string{string(intoto.AlgorithmSHA1): "410f93f5360bc4f097fa4f553bfcd709f0f8d230"},
					Name:   "hello.txt",
					Uri:    "/home/hello.txt",
				},
				{
					Digest: map[string]string{
						string(intoto.AlgorithmSHA1):   "410f93f5360bc4f097fa4f553bfcd709f0f8d230",
						string(intoto.AlgorithmSHA256): "7355804febd9ee8357b737b61ea7ca0f1b3ff5c898bc8f003a00beabba7e91fd",
					},
					Name: "bye.txt",
					Uri:  "/home/bye.txt",
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rds := tc.hsl.ToResourceDescriptors()
			require.Len(t, rds, len(tc.expect))
			i := 0
			for path, set := range *tc.hsl {
				for algo, value := range set {
					require.Equal(t, tc.expect[i].Digest[string(algo)], value)
					require.Equal(t, tc.expect[i].Uri, path)
				}
				i++
			}
		})
	}
}
