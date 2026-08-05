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

package stateview

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/coordinator/dependencytracker"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/coordinator/grapher"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/coordinator/statevisibilitytracker"
	"github.com/LFDT-Paladin/paladin/core/internal/sequencer/testutil"
	"github.com/LFDT-Paladin/paladin/core/mocks/componentsmocks"
	engineProto "github.com/LFDT-Paladin/paladin/core/pkg/proto/engine"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/query"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	testStateID   = pldtypes.MustParseHexBytes("0x" + strings.Repeat("aa", 32))
	testSchemaID  = pldtypes.MustParseBytes32("0x" + strings.Repeat("bb", 32))
	testSessionID = "session-1"
)

// serverTestSetup builds a server over a real grapher + visibility tracker holding one labelled,
// CREATE-locked state visible to node1, with a mocked state manager for the match evaluation. A
// session (testSessionID) is opened for node1, freezing that state as its candidate snapshot.
func serverTestSetup(t *testing.T) (Server, *testutil.SentMessageRecorder, *componentsmocks.StateManager) {
	ctx := t.Context()
	recorder := testutil.NewSentMessageRecorder()
	tracker := statevisibilitytracker.NewStore()
	g := grapher.NewGrapher(dependencytracker.NewDependencyTracker(), tracker, 10)

	states := []*prototk.EndorsableState{{Id: testStateID.String(), SchemaId: testSchemaID.String(), StateDataJson: `{"some":"data"}`}}
	tracker.RecordAssemblyOutput(ctx, states, []*prototk.StateLabels{{}}, [][]string{{"alice@node1"}})
	g.LockMintsOnCreate(ctx, states, uuid.New())

	stateManager := componentsmocks.NewStateManager(t)
	s := NewServer("test-domain", testContractAddress, recorder, g, stateManager)
	s.OpenSession(ctx, testSessionID, "node1")
	return s, recorder, stateManager
}

func TestServer_HandleQueryAvailableStates_ServesMatchingStates(t *testing.T) {
	ctx := t.Context()
	s, recorder, stateManager := serverTestSetup(t)

	// The matcher receives the visible candidates and returns the winners; the response carries
	// their full data plus created.
	stateManager.EXPECT().FindMatchingInMemoryStates(mock.Anything, "test-domain", testSchemaID, mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, _ string, _ pldtypes.Bytes32, _ *query.QueryJSON, candidates []*prototk.SnapshotState) ([]*prototk.QueriedState, error) {
			require.Len(t, candidates, 1)
			assert.Equal(t, testStateID.String(), candidates[0].GetState().GetId())
			return []*prototk.QueriedState{{State: candidates[0].GetState(), Created: candidates[0].GetCreated()}}, nil
		}).Once()

	s.HandleQueryAvailableStates(ctx, "node1", &engineProto.QueryAvailableStatesRequest{
		ContractAddress: testContractAddress,
		RequestId:       "req1",
		SchemaId:        testSchemaID.String(),
		QueryJson:       `{}`,
		SessionId:       testSessionID,
	})

	require.Empty(t, recorder.SentStateViewErrors())
	responses := recorder.SentQueryAvailableStatesResponses()
	require.Len(t, responses, 1)
	assert.Equal(t, "req1", responses[0].GetRequestId())
	assert.Equal(t, testContractAddress, responses[0].GetContractAddress())
	require.Len(t, responses[0].GetStates(), 1)
	assert.Equal(t, testStateID.String(), responses[0].GetStates()[0].GetState().GetId())
	assert.Equal(t, `{"some":"data"}`, responses[0].GetStates()[0].GetState().GetStateDataJson())
	assert.NotZero(t, responses[0].GetStates()[0].GetCreated())
}

func TestServer_HandleQueryAvailableStates_UnentitledNodeGetsNoCandidates(t *testing.T) {
	ctx := t.Context()
	s, recorder, stateManager := serverTestSetup(t)

	// node2 has no visibility (default-deny): its session snapshot captures zero candidates — an
	// empty response, never an error, and never a data leak.
	s.OpenSession(ctx, "session-2", "node2")
	stateManager.EXPECT().FindMatchingInMemoryStates(mock.Anything, "test-domain", testSchemaID, mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, _ string, _ pldtypes.Bytes32, _ *query.QueryJSON, candidates []*prototk.SnapshotState) ([]*prototk.QueriedState, error) {
			assert.Empty(t, candidates)
			return nil, nil
		}).Once()

	s.HandleQueryAvailableStates(ctx, "node2", &engineProto.QueryAvailableStatesRequest{
		ContractAddress: testContractAddress,
		RequestId:       "req1",
		SchemaId:        testSchemaID.String(),
		QueryJson:       `{}`,
		SessionId:       "session-2",
	})

	require.Empty(t, recorder.SentStateViewErrors())
	responses := recorder.SentQueryAvailableStatesResponses()
	require.Len(t, responses, 1)
	assert.Empty(t, responses[0].GetStates())
}

func TestServer_HandleQueryAvailableStates_BadSchemaID(t *testing.T) {
	ctx := t.Context()
	s, recorder, _ := serverTestSetup(t)

	s.HandleQueryAvailableStates(ctx, "node1", &engineProto.QueryAvailableStatesRequest{
		ContractAddress: testContractAddress,
		RequestId:       "req1",
		SchemaId:        "not-a-schema",
		QueryJson:       `{}`,
		SessionId:       testSessionID,
	})

	require.Empty(t, recorder.SentQueryAvailableStatesResponses())
	errs := recorder.SentStateViewErrors()
	require.Len(t, errs, 1)
	assert.Equal(t, "req1", errs[0].GetRequestId())
	assert.Regexp(t, "PD012656", errs[0].GetErrorMessage())
}

func TestServer_HandleQueryAvailableStates_BadQueryJSON(t *testing.T) {
	ctx := t.Context()
	s, recorder, _ := serverTestSetup(t)

	s.HandleQueryAvailableStates(ctx, "node1", &engineProto.QueryAvailableStatesRequest{
		ContractAddress: testContractAddress,
		RequestId:       "req1",
		SchemaId:        testSchemaID.String(),
		QueryJson:       `!!!not json`,
		SessionId:       testSessionID,
	})

	require.Empty(t, recorder.SentQueryAvailableStatesResponses())
	errs := recorder.SentStateViewErrors()
	require.Len(t, errs, 1)
	assert.Regexp(t, "PD012656", errs[0].GetErrorMessage())
}

func TestServer_HandleQueryAvailableStates_EvaluationError(t *testing.T) {
	ctx := t.Context()
	s, recorder, stateManager := serverTestSetup(t)

	stateManager.EXPECT().FindMatchingInMemoryStates(mock.Anything, "test-domain", testSchemaID, mock.Anything, mock.Anything).
		Return(nil, errors.New("pop")).Once()

	s.HandleQueryAvailableStates(ctx, "node1", &engineProto.QueryAvailableStatesRequest{
		ContractAddress: testContractAddress,
		RequestId:       "req1",
		SchemaId:        testSchemaID.String(),
		QueryJson:       `{}`,
		SessionId:       testSessionID,
	})

	require.Empty(t, recorder.SentQueryAvailableStatesResponses())
	errs := recorder.SentStateViewErrors()
	require.Len(t, errs, 1)
	assert.Equal(t, "req1", errs[0].GetRequestId())
	assert.Regexp(t, "pop", errs[0].GetErrorMessage())
}

func TestServer_HandleQueryAvailableStates_UnknownSession(t *testing.T) {
	ctx := t.Context()
	s, recorder, _ := serverTestSetup(t)

	s.HandleQueryAvailableStates(ctx, "node1", &engineProto.QueryAvailableStatesRequest{
		ContractAddress: testContractAddress,
		RequestId:       "req1",
		SchemaId:        testSchemaID.String(),
		QueryJson:       `{}`,
		SessionId:       "no-such-session",
	})

	require.Empty(t, recorder.SentQueryAvailableStatesResponses())
	errs := recorder.SentStateViewErrors()
	require.Len(t, errs, 1)
	assert.Regexp(t, "PD012657", errs[0].GetErrorMessage())
}

func TestServer_HandleQueryAvailableStates_WrongNode(t *testing.T) {
	ctx := t.Context()
	s, recorder, _ := serverTestSetup(t)

	// The session was opened for node1; node2 must not be able to query it.
	s.HandleQueryAvailableStates(ctx, "node2", &engineProto.QueryAvailableStatesRequest{
		ContractAddress: testContractAddress,
		RequestId:       "req1",
		SchemaId:        testSchemaID.String(),
		QueryJson:       `{}`,
		SessionId:       testSessionID,
	})

	require.Empty(t, recorder.SentQueryAvailableStatesResponses())
	errs := recorder.SentStateViewErrors()
	require.Len(t, errs, 1)
	assert.Regexp(t, "PD012658", errs[0].GetErrorMessage())
}

func TestServer_CloseSession_MakesSubsequentQueriesUnknown(t *testing.T) {
	ctx := t.Context()
	s, recorder, _ := serverTestSetup(t)

	s.CloseSession(ctx, testSessionID)

	s.HandleQueryAvailableStates(ctx, "node1", &engineProto.QueryAvailableStatesRequest{
		ContractAddress: testContractAddress,
		RequestId:       "req1",
		SchemaId:        testSchemaID.String(),
		QueryJson:       `{}`,
		SessionId:       testSessionID,
	})

	require.Empty(t, recorder.SentQueryAvailableStatesResponses())
	errs := recorder.SentStateViewErrors()
	require.Len(t, errs, 1)
	assert.Regexp(t, "PD012657", errs[0].GetErrorMessage())
}

func TestServer_HandleGetSpentStateIDs_ServesFrozenSpentSet(t *testing.T) {
	ctx := t.Context()
	recorder := testutil.NewSentMessageRecorder()
	tracker := statevisibilitytracker.NewStore()
	g := grapher.NewGrapher(dependencytracker.NewDependencyTracker(), tracker, 10)

	spentStateID := pldtypes.MustParseHexBytes("0x" + strings.Repeat("cc", 32))
	g.LockMintsOnReadAndSpend(ctx, nil, []*prototk.EndorsableState{{Id: spentStateID.String()}}, uuid.New())

	s := NewServer("test-domain", testContractAddress, recorder, g, componentsmocks.NewStateManager(t))
	s.OpenSession(ctx, testSessionID, "node1")

	// A state spend-locked after the session opened must not appear: the view froze at open.
	lateSpentStateID := pldtypes.MustParseHexBytes("0x" + strings.Repeat("dd", 32))
	g.LockMintsOnReadAndSpend(ctx, nil, []*prototk.EndorsableState{{Id: lateSpentStateID.String()}}, uuid.New())

	s.HandleGetSpentStateIDs(ctx, "node1", &engineProto.GetSpentStateIDsRequest{
		ContractAddress: testContractAddress,
		RequestId:       "req1",
		SessionId:       testSessionID,
	})

	require.Empty(t, recorder.SentStateViewErrors())
	responses := recorder.SentGetSpentStateIDsResponses()
	require.Len(t, responses, 1)
	assert.Equal(t, "req1", responses[0].GetRequestId())
	assert.Equal(t, testContractAddress, responses[0].GetContractAddress())
	require.Len(t, responses[0].GetSpentStateIds(), 1)
	assert.Equal(t, []byte(spentStateID), responses[0].GetSpentStateIds()[0])
}

func TestServer_HandleGetSpentStateIDs_UnknownSession(t *testing.T) {
	ctx := t.Context()
	s, recorder, _ := serverTestSetup(t)

	s.HandleGetSpentStateIDs(ctx, "node1", &engineProto.GetSpentStateIDsRequest{
		ContractAddress: testContractAddress,
		RequestId:       "req1",
		SessionId:       "unknown-session",
	})

	require.Empty(t, recorder.SentGetSpentStateIDsResponses())
	errs := recorder.SentStateViewErrors()
	require.Len(t, errs, 1)
	assert.Equal(t, "req1", errs[0].GetRequestId())
	assert.Regexp(t, "PD012657", errs[0].GetErrorMessage())
}

func TestServer_HandleGetSpentStateIDs_WrongNode(t *testing.T) {
	ctx := t.Context()
	s, recorder, _ := serverTestSetup(t)

	s.HandleGetSpentStateIDs(ctx, "node2", &engineProto.GetSpentStateIDsRequest{
		ContractAddress: testContractAddress,
		RequestId:       "req1",
		SessionId:       testSessionID,
	})

	require.Empty(t, recorder.SentGetSpentStateIDsResponses())
	errs := recorder.SentStateViewErrors()
	require.Len(t, errs, 1)
	assert.Regexp(t, "PD012658", errs[0].GetErrorMessage())
}
