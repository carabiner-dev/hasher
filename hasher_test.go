// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package hasher

import (
	"io"
	"os"
	"strings"
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/require"
)

func TestHashReader(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		data    string
		expect  map[intoto.HashAlgorithm]string
		opts    Options
		mustErr bool
	}{
		{
			"normal", "This is some test data to hash",
			map[intoto.HashAlgorithm]string{
				intoto.AlgorithmSHA256: "542386a2a9f417ebb4482309b2dc36857f24e28b256f7ffd42b795b0c58543fd",
				intoto.AlgorithmSHA512: "45ad294d499418d267ae4470234fa97d5976c8e1ae2afe30c054a41e0ab97f27aa8b4533acabdfb661d04a9f6fb09502b7a30e12589edefb6745578973f9a117",
			},
			defaultOptions, false,
		},
		{
			"algo-in-opts", "This is some test data to hash",
			map[intoto.HashAlgorithm]string{
				intoto.AlgorithmSHA384: "2d82d856ce77f76343c5b32c5ed57e052e48f8d427bc7061939a391d3884b0a99024c2241ea01cf44c60e196889536ad",
			},
			Options{Algorithms: []intoto.HashAlgorithm{intoto.AlgorithmSHA384}},
			false,
		},
		{
			"no-algos", "This is some test data to hash", nil,
			Options{Algorithms: []intoto.HashAlgorithm{}},
			true,
		},
		{
			"invalid-algo", "This is some test data to hash",
			map[intoto.HashAlgorithm]string{},
			Options{Algorithms: []intoto.HashAlgorithm{intoto.HashAlgorithm("mickey")}},
			true,
		},
		{
			"zero-length", "",
			map[intoto.HashAlgorithm]string{
				intoto.AlgorithmSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				intoto.AlgorithmSHA512: "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
			},
			defaultOptions, false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := New()
			h.Options = tc.opts

			r := strings.NewReader(tc.data)
			res, err := h.hashReader(r)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			require.Len(t, *res, len(tc.expect))

			for algo, val := range tc.expect {
				require.Equal(t, (*res)[algo], val)
			}
		})
	}
}

func TestHashReaders(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		data    []string
		mustErr bool
		options Options
		expect  []map[intoto.HashAlgorithm]string
	}{
		{
			"normal",
			[]string{"uno", "dos", "tres"},
			false, defaultOptions,
			[]map[intoto.HashAlgorithm]string{
				{
					intoto.AlgorithmSHA256: "bf0ec3694e122e067d9964a38ec7d8415781df4b24f442ad767b4621fb98f8c5",
					intoto.AlgorithmSHA512: "61ee6f6514744185e8f180da9c41b13f5f0ef11aa1db2e770480cc4a7a9876802b3982c01dd5eed69da919701cf44dc07afb4b67b25af5f4bf045c4f2023c0d0",
				},
				{
					intoto.AlgorithmSHA256: "c1299854f2b209632ab22aeb848c24c2b02da4b37ecf93a830ee9c7f6f809924",
					intoto.AlgorithmSHA512: "b4da20f6a387c1ce2814be295c3ad0321feb87536e00eb5932642d51b0ff94e2b2d864ee555d154a38258d70be3bcc84baf68fb14825d7abab2671b03eefb782",
				},
				{
					intoto.AlgorithmSHA256: "3d5f1d095f03cbeab065f280e5c42801aa0122b683af43b458dfa65fa438b5e8",
					intoto.AlgorithmSHA512: "6ed06906fc1e0eda3ffe4ac332d6fa06b814fd42f9c14fb994e3966770e042f774b356ee5c8ec5a1822479fec07a444eece2989fa10735f02699ff537978a7f7",
				},
			},
		},
		{
			"other-algo",
			[]string{"uno", "dos"},
			false,
			Options{Algorithms: []intoto.HashAlgorithm{intoto.AlgorithmSHA384}},
			[]map[intoto.HashAlgorithm]string{
				{intoto.AlgorithmSHA384: "c8417791191bd495021ee2a56271f570db971cf8d15c68cc1ce9efeaad559f3dcfc7112b75856624875985c0fc3d5cca"},
				{intoto.AlgorithmSHA384: "dedb025dd087ef2ee558bd79a71e16f5e2a90ed2d214bb05e1446cb6bbd6bbd2e7686e87b84889210da19ca0656f8b06"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			readers := []io.Reader{}
			for _, s := range tc.data {
				readers = append(readers, strings.NewReader(s))
			}

			h := New()
			h.Options = tc.options
			res, err := h.HashReaders(readers)
			if tc.mustErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Len(t, *res, len(readers))

			for i, hashSet := range *res {
				require.Len(t, hashSet, len(h.Options.Algorithms))
				for algo, value := range hashSet {
					require.Equal(t, tc.expect[i][algo], value)
				}
			}
		})
	}
}

func TestHashFiles(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		data    []string
		mustErr bool
		options Options
		expect  []map[intoto.HashAlgorithm]string
	}{
		{
			"normal",
			[]string{"uno", "dos", "tres"},
			false, defaultOptions,
			[]map[intoto.HashAlgorithm]string{
				{
					intoto.AlgorithmSHA256: "bf0ec3694e122e067d9964a38ec7d8415781df4b24f442ad767b4621fb98f8c5",
					intoto.AlgorithmSHA512: "61ee6f6514744185e8f180da9c41b13f5f0ef11aa1db2e770480cc4a7a9876802b3982c01dd5eed69da919701cf44dc07afb4b67b25af5f4bf045c4f2023c0d0",
				},
				{
					intoto.AlgorithmSHA256: "c1299854f2b209632ab22aeb848c24c2b02da4b37ecf93a830ee9c7f6f809924",
					intoto.AlgorithmSHA512: "b4da20f6a387c1ce2814be295c3ad0321feb87536e00eb5932642d51b0ff94e2b2d864ee555d154a38258d70be3bcc84baf68fb14825d7abab2671b03eefb782",
				},
				{
					intoto.AlgorithmSHA256: "3d5f1d095f03cbeab065f280e5c42801aa0122b683af43b458dfa65fa438b5e8",
					intoto.AlgorithmSHA512: "6ed06906fc1e0eda3ffe4ac332d6fa06b814fd42f9c14fb994e3966770e042f774b356ee5c8ec5a1822479fec07a444eece2989fa10735f02699ff537978a7f7",
				},
			},
		},
		{
			"other-algo",
			[]string{"uno", "dos"},
			false,
			Options{Algorithms: []intoto.HashAlgorithm{intoto.AlgorithmSHA384}},
			[]map[intoto.HashAlgorithm]string{
				{intoto.AlgorithmSHA384: "c8417791191bd495021ee2a56271f570db971cf8d15c68cc1ce9efeaad559f3dcfc7112b75856624875985c0fc3d5cca"},
				{intoto.AlgorithmSHA384: "dedb025dd087ef2ee558bd79a71e16f5e2a90ed2d214bb05e1446cb6bbd6bbd2e7686e87b84889210da19ca0656f8b06"},
			},
		},
		{
			"too-many", make([]string, maxOpenFiles+1), true,
			Options{Algorithms: []intoto.HashAlgorithm{intoto.AlgorithmSHA384}},
			[]map[intoto.HashAlgorithm]string{
				{intoto.AlgorithmSHA384: "c8417791191bd495021ee2a56271f570db971cf8d15c68cc1ce9efeaad559f3dcfc7112b75856624875985c0fc3d5cca"},
				{intoto.AlgorithmSHA384: "dedb025dd087ef2ee558bd79a71e16f5e2a90ed2d214bb05e1446cb6bbd6bbd2e7686e87b84889210da19ca0656f8b06"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Write the data to temp files
			dir := t.TempDir()
			files := make([]string, len(tc.data))
			for i, d := range tc.data {
				f, err := os.CreateTemp(dir, "data-*.txt")
				require.NoError(t, err)

				require.NoError(t, os.WriteFile(f.Name(), []byte(d), os.FileMode(0o644)))
				require.NoError(t, f.Close())
				files[i] = f.Name()
			}

			h := New()
			h.Options = tc.options
			res, err := h.HashFiles(files)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			for i, path := range files {
				require.Len(t, (*res)[path], len(h.Options.Algorithms))
				for algo, value := range (*res)[path] {
					require.Equal(t, tc.expect[i][algo], value)
				}
			}
		})
	}
}

func checkHashSet(t *testing.T, hs *HashSet) {
	t.Helper()
	require.Equal(t, "12345", (*hs)[intoto.AlgorithmSHA1])
	require.Equal(t, "567788", (*hs)[intoto.AlgorithmSHA256])
}

func TestNewHashSet(t *testing.T) {
	t.Parallel()
	t.Run("string-string", func(t *testing.T) {
		t.Parallel()
		hs := NewHashSet(map[string]string{
			"sha1":   "12345",
			"sha256": "567788",
		})
		checkHashSet(t, hs)
	})
	t.Run("intoto-string", func(t *testing.T) {
		t.Parallel()
		hs := NewHashSet(map[intoto.HashAlgorithm]string{
			intoto.AlgorithmSHA1:   "12345",
			intoto.AlgorithmSHA256: "567788",
		})
		checkHashSet(t, hs)
	})
}
