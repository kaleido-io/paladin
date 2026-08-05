/*
 * Copyright © 2026 Kaleido, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Package statevisibilitytracker is the single control point for private state visibility in the sequencer.
//
// It tracks which nodes are permitted to hold each private state's data, derived from the assembly
// response DistributionList. The default posture is deny: a state whose AllowedNodes is nil or empty
// is invisible to every node. This is the correct fail-safe for unknown distributions — no state data
// is leaked by default.
//
// The store is internally thread-safe; callers do not need external synchronisation.
package statevisibilitytracker

import (
	"context"
	"sync"

	"github.com/LFDT-Paladin/paladin/common/go/pkg/log"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
)

// StateVisibilityStore is the single interface for all private state visibility operations.
// All methods are thread-safe.
//
// States are held natively as *prototk.SnapshotState (an EndorsableState plus the AllowedNodes set of
// nodes permitted to hold the private data, derived from the assembly response DistributionList). A nil
// or empty AllowedNodes means the distribution is unknown and the state is excluded from all exports —
// this is the default-deny posture.
type StateVisibilityStore interface {
	// RecordAssemblyOutput is the only path by which newly minted state visibility is written.
	// The three slices are index-aligned per output state: the resolved endorsable state, its proto
	// labels, and its distribution list. This derives AllowedNodes from the distribution list and
	// stamps each state with a coordinator-local created time used to order states when querying.
	RecordAssemblyOutput(ctx context.Context, states []*prototk.EndorsableState, labels []*prototk.StateLabels, distributionLists [][]string)

	// GetForNode returns all states that node is explicitly listed in AllowedNodes for. States with
	// nil or empty AllowedNodes are always excluded (default-deny), as are states with no labels — a
	// state recorded through assembly always carries (possibly empty) labels, so a label-less state is
	// internally inconsistent and is never advertised.
	GetForNode(node string) []*prototk.SnapshotState

	// RangeForNode calls fn for every state visible to node, under the same node/label filter as
	// GetForNode, without materialising an intermediate slice. Used where the caller applies a
	// further filter and builds its own result, so the full-map copy GetForNode returns would be
	// thrown away. fn must not call back into the store (the read lock is held for the duration).
	RangeForNode(node string, fn func(*prototk.SnapshotState))

	// ImportIfAbsent records state only if no entry already exists for stateID.
	// Existing entries always take precedence — a coordinator's own knowledge must never be
	// overwritten by a handover import. Returns true if the state was stored.
	ImportIfAbsent(stateID string, state *prototk.SnapshotState) bool

	// Delete removes stateID. No-op if absent.
	Delete(stateID string)
}

type store struct {
	mu         sync.RWMutex
	statesByID map[string]*prototk.SnapshotState
}

// NewStore returns a new, empty StateVisibilityStore.
func NewStore() StateVisibilityStore {
	return &store{
		statesByID: make(map[string]*prototk.SnapshotState),
	}
}

func (s *store) RecordAssemblyOutput(ctx context.Context, states []*prototk.EndorsableState, labels []*prototk.StateLabels, distributionLists [][]string) {
	// Build snapshots before acquiring the lock — no shared state is read here. states[i], labels[i]
	// and distributionLists[i] describe the same state; a missing distribution list leaves AllowedNodes
	// empty (default-deny). We stamp each state's created here: it is a coordinator-local ordering hint
	// carried on the advertised refs, distinct from the persisted states.created (a local insert-time
	// written by the DB layer on every node). Stamped per state so states recorded together keep a
	// stable relative order.
	snapshots := make([]*prototk.SnapshotState, len(states))
	for i, state := range states {
		var distributionList []string
		if i < len(distributionLists) {
			distributionList = distributionLists[i]
		}
		var stateLabels *prototk.StateLabels
		if i < len(labels) {
			stateLabels = labels[i]
		}
		snapshots[i] = &prototk.SnapshotState{
			State:        state,
			AllowedNodes: allowedNodesFromDistributionList(ctx, distributionList),
			Labels:       stateLabels,
			Created:      pldtypes.TimestampNow().UnixNano(),
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, snapshot := range snapshots {
		s.statesByID[snapshot.GetState().GetId()] = snapshot
	}
}

func (s *store) GetForNode(node string) []*prototk.SnapshotState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*prototk.SnapshotState, 0, len(s.statesByID))
	for _, snapshot := range s.statesByID {
		if snapshot.GetLabels() != nil && nodeInAllowedList(snapshot.GetAllowedNodes(), node) {
			result = append(result, snapshot)
		}
	}
	return result
}

func (s *store) RangeForNode(node string, fn func(*prototk.SnapshotState)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, snapshot := range s.statesByID {
		if snapshot.GetLabels() != nil && nodeInAllowedList(snapshot.GetAllowedNodes(), node) {
			fn(snapshot)
		}
	}
}

func (s *store) ImportIfAbsent(stateID string, state *prototk.SnapshotState) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.statesByID[stateID]; exists {
		return false
	}
	s.statesByID[stateID] = state
	return true
}

func (s *store) Delete(stateID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.statesByID, stateID)
}

// allowedNodesFromDistributionList extracts the node names from a state's DistributionList — the
// authoritative set of nodes permitted to hold that state's private data. If a locator cannot be
// parsed, a warning is logged and that recipient is skipped, so the state is invisible to the
// unparseable node (default-deny).
func allowedNodesFromDistributionList(ctx context.Context, distributionList []string) []string {
	var allowedNodes []string
	for _, recipient := range distributionList {
		node, err := pldtypes.PrivateIdentityLocator(recipient).Node(ctx, false)
		if err != nil {
			log.L(ctx).Warnf("statevisibilitytracker: could not extract node from locator %q: %s", recipient, err)
			continue
		}
		allowedNodes = append(allowedNodes, node)
	}
	return allowedNodes
}

// nodeInAllowedList reports whether node appears in the allowed list.
// A nil or empty allowed list means unknown distribution — the state is excluded (default-deny).
func nodeInAllowedList(allowed []string, node string) bool {
	for _, n := range allowed {
		if n == node {
			return true
		}
	}
	return false
}
