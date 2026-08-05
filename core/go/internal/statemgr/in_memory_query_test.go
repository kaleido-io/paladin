// Copyright contributors to Paladin, an LFDT project
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package statemgr

import (
	"testing"

	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldapi"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/query"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindMatchingInMemoryStates_LabelFilter(t *testing.T) {
	ctx, ss, _, schema1, contractAddress, done := coinTestSetup(t)
	defer done()

	s10 := mkFakeCoin(t, ctx, schema1, contractAddress, false, 10)
	s20 := mkFakeCoin(t, ctx, schema1, contractAddress, false, 20)
	candidates := []*prototk.SnapshotState{snapshotStateOf(s10, 1), snapshotStateOf(s20, 2)}

	matches, err := ss.FindMatchingInMemoryStates(ctx, "domain1", schema1.ID(),
		query.NewQueryBuilder().Equal("amount", 20).Query(), candidates)
	require.NoError(t, err)
	require.Len(t, matches, 1)
	assert.Equal(t, s20.ID.String(), matches[0].State.GetId())
}

func TestFindMatchingInMemoryStates_SchemaFilter(t *testing.T) {
	ctx, ss, _, schema1, contractAddress, done := coinTestSetup(t)
	defer done()

	schema2, err := newABISchema(ctx, "domain1", testABIParam(t, fakeCoinABI2))
	require.NoError(t, err)
	err = ss.persistSchemas(ctx, ss.p.NOTX(), []*pldapi.Schema{schema2.Schema})
	require.NoError(t, err)

	s1 := mkFakeCoin(t, ctx, schema1, contractAddress, false, 10)
	candidates := []*prototk.SnapshotState{snapshotStateOf(s1, 1)}

	// Querying a different schema matches nothing.
	matches, err := ss.FindMatchingInMemoryStates(ctx, "domain1", schema2.ID(),
		query.NewQueryBuilder().Query(), candidates)
	require.NoError(t, err)
	assert.Empty(t, matches)
}

func TestFindMatchingInMemoryStates_SortAndLimit(t *testing.T) {
	ctx, ss, _, schema1, contractAddress, done := coinTestSetup(t)
	defer done()

	s10 := mkFakeCoin(t, ctx, schema1, contractAddress, false, 10)
	s20 := mkFakeCoin(t, ctx, schema1, contractAddress, false, 20)
	s30 := mkFakeCoin(t, ctx, schema1, contractAddress, false, 30)
	candidates := []*prototk.SnapshotState{snapshotStateOf(s10, 1), snapshotStateOf(s20, 2), snapshotStateOf(s30, 3)}

	// Sort descending on the amount label, limit 2.
	matches, err := ss.FindMatchingInMemoryStates(ctx, "domain1", schema1.ID(),
		query.NewQueryBuilder().Limit(2).Sort("-amount").Query(), candidates)
	require.NoError(t, err)
	require.Len(t, matches, 2)
	assert.Equal(t, s30.ID.String(), matches[0].State.GetId())
	assert.Equal(t, s20.ID.String(), matches[1].State.GetId())
}

func TestFindMatchingInMemoryStates_DefaultCreatedSort(t *testing.T) {
	ctx, ss, _, schema1, contractAddress, done := coinTestSetup(t)
	defer done()

	late := mkFakeCoin(t, ctx, schema1, contractAddress, false, 10)
	early := mkFakeCoin(t, ctx, schema1, contractAddress, false, 20)
	candidates := []*prototk.SnapshotState{snapshotStateOf(late, 2000), snapshotStateOf(early, 1000)}

	// No sort instruction defaults to ascending ".created", mirroring the DB query default.
	matches, err := ss.FindMatchingInMemoryStates(ctx, "domain1", schema1.ID(),
		query.NewQueryBuilder().Query(), candidates)
	require.NoError(t, err)
	require.Len(t, matches, 2)
	assert.Equal(t, early.ID.String(), matches[0].State.GetId())
	assert.Equal(t, late.ID.String(), matches[1].State.GetId())
}

func TestFindMatchingInMemoryStates_EvalError(t *testing.T) {
	ctx, ss, _, schema1, contractAddress, done := coinTestSetup(t)
	defer done()

	s1 := mkFakeCoin(t, ctx, schema1, contractAddress, false, 10)
	candidates := []*prototk.SnapshotState{snapshotStateOf(s1, 1)}

	_, err := ss.FindMatchingInMemoryStates(ctx, "domain1", schema1.ID(),
		query.NewQueryBuilder().Equal("wrong", "any").Query(), candidates)
	assert.Regexp(t, "PD010700", err)
}

func TestFindMatchingInMemoryStates_UnparseableCandidateSkipped(t *testing.T) {
	ctx, ss, _, schema1, contractAddress, done := coinTestSetup(t)
	defer done()

	good := mkFakeCoin(t, ctx, schema1, contractAddress, false, 20)
	// A candidate whose state ID cannot be parsed is skipped rather than failing the whole query.
	bad := snapshotStateOf(good, 1)
	bad.State = &prototk.EndorsableState{Id: "not-hex", SchemaId: schema1.ID().String()}

	matches, err := ss.FindMatchingInMemoryStates(ctx, "domain1", schema1.ID(),
		query.NewQueryBuilder().Query(), []*prototk.SnapshotState{bad, snapshotStateOf(good, 2)})
	require.NoError(t, err)
	require.Len(t, matches, 1)
	assert.Equal(t, good.ID.String(), matches[0].State.GetId())
}

func TestFindMatchingInMemoryStates_UnknownSchema(t *testing.T) {
	ctx, ss, _, _, _, done := coinTestSetup(t)
	defer done()

	_, err := ss.FindMatchingInMemoryStates(ctx, "domain1", pldtypes.Bytes32(pldtypes.RandBytes(32)),
		query.NewQueryBuilder().Query(), nil)
	require.Error(t, err)
}
