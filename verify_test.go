// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package hasher

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVerifyReader(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		data    string
		hashes  HashSet
		expect  bool
		mustErr bool
	}{
		{
			"match", "Hello, and goodbye", HashSet{
				"sha1": "5ec989318dc1c90e77d30e7370316c0af35a288f",
			}, true, false,
		},
		{
			"match-multi-algos", "Hello, and goodbye", HashSet{
				"sha1":   "5ec989318dc1c90e77d30e7370316c0af35a288f",
				"sha256": "79a6961096e3c039279a85201ff9e16bc6d18791d8775e53fea6a317e91b0366",
				"sha512": "420b4956644a0612ca4e929ae00361182cdfdede59276702ab8de41cf705c9281592a8d903e81ea5a9884e40e118aa341ed5f6916ddb2b877fa9a5ab50437779",
			}, true, false,
		},
		{
			"no-match", "Hello, and goodbye but more!", HashSet{
				"sha1": "5ec989318dc1c90e77d30e7370316c0af35a288f",
			}, false, false,
		},
		{
			"no-match-multi-algos", "Hello, and goodbye but more!", HashSet{
				"sha1":   "5ec989318dc1c90e77d30e7370316c0af35a288f",
				"sha256": "79a6961096e3c039279a85201ff9e16bc6d18791d8775e53fea6a317e91b0366",
				"sha512": "420b4956644a0612ca4e929ae00361182cdfdede59276702ab8de41cf705c9281592a8d903e81ea5a9884e40e118aa341ed5f6916ddb2b877fa9a5ab50437779",
			}, false, false,
		},
		{
			"unknown-algo", "Hello, and goodbye but more!", HashSet{
				"sha420": "79a6961096e3c039279a85201ff9e16bc6d18791d8775e53fea6a317e91b0366",
			}, false, true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			res, err := New().VerifyReader(strings.NewReader(tc.data), &tc.hashes)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expect, res)
		})
	}
}
