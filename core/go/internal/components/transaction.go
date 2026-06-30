/*
 * Copyright © 2024 Kaleido, Inc.
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

package components

import (
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldapi"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
	"github.com/google/uuid"
	"github.com/hyperledger/firefly-signer/pkg/abi"
)

type TransactionStateRefs struct {
	Confirmed []pldtypes.HexBytes
	Read      []pldtypes.HexBytes
	Spent     []pldtypes.HexBytes
	Info      []pldtypes.HexBytes
}

type PreparedTransactionWithRefs struct {
	*pldapi.PreparedTransactionBase
	StateRefs TransactionStateRefs `json:"stateRefs"` // the states associated with the original private transaction
}

type FullState struct {
	ID     pldtypes.HexBytes `json:"id"`
	Schema pldtypes.Bytes32  `json:"schema"`
	Data   pldtypes.RawJSON  `json:"data"`
}

type EthTransaction struct {
	FunctionABI *abi.Entry
	To          pldtypes.EthAddress
	Inputs      *abi.ComponentValue
}

type EthDeployTransaction struct {
	ConstructorABI *abi.Entry
	Bytecode       pldtypes.HexBytes
	Inputs         *abi.ComponentValue
}

// TransactionPostAssembly holds the proto assembly response alongside the go representations
// of the same states. This approaches minimises CPU time spent converting between the two representations
// at the expense of memory usage, since the same private state data is stored multiple times.
type TransactionPostAssembly struct {
	// Immutable proto: the wire format received/sent in AssembleResponse.
	AssembleResponse *prototk.TransactionPostAssembly

	// TODO AM - pretty sure this is going to tie into protos for snapshots
	// Go-typed state slices for states that need full FullState (HexBytes ID + schema + data).
	// InputStates and ReadStates are not stored here; consumers use AssembleResponse.GetInputStates()
	// and AssembleResponse.GetReadStates() directly since EndorsableState is sufficient for all uses.
	OutputStates []*FullState // resolved from OutputStatesPotential in AssemblyResponse
	InfoStates   []*FullState // resolved from InfoStatesPotential in AssemblyResponse

	// Endorsements accumulated during the EndorsementGathering phase by the coordinator.
	// Seeded from AssemblyResponse.Endorsements so any pre-assembly endorsements included
	// by the originator are also counted.
	CollectedEndorsements []*prototk.AttestationResult

	// Lazy EndorsableState caches for OutputStates/InfoStates — computed on first call to the
	// accessor methods below, avoiding repeated conversion at endorsement/prepare time.
	outputStatesEndorsable []*prototk.EndorsableState
	infoStatesEndorsable   []*prototk.EndorsableState
}

// EndorsableOutputStates returns OutputStates as []*prototk.EndorsableState, converting and
// caching on first call. Input/ReadStates are accessed directly from AssemblyResponse (already EndorsableState).
func (pa *TransactionPostAssembly) EndorsableOutputStates() []*prototk.EndorsableState {
	if pa.outputStatesEndorsable == nil {
		pa.outputStatesEndorsable = FullStatesToEndorsable(pa.OutputStates)
	}
	return pa.outputStatesEndorsable
}

// EndorsableInfoStates returns InfoStates as []*prototk.EndorsableState, converting and
// caching on first call.
func (pa *TransactionPostAssembly) EndorsableInfoStates() []*prototk.EndorsableState {
	if pa.infoStatesEndorsable == nil {
		pa.infoStatesEndorsable = FullStatesToEndorsable(pa.InfoStates)
	}
	return pa.infoStatesEndorsable
}

// FullStatesToEndorsable converts []*FullState to []*prototk.EndorsableState.
func FullStatesToEndorsable(states []*FullState) []*prototk.EndorsableState {
	endorsable := make([]*prototk.EndorsableState, len(states))
	for i, s := range states {
		endorsable[i] = &prototk.EndorsableState{
			Id:            s.ID.String(),
			SchemaId:      s.Schema.String(),
			StateDataJson: string(s.Data),
		}
	}
	return endorsable
}

// PrivateTransaction is the critical exchange object between the engine and the domain manager,
// as it hops between the states in the state machine (on multiple paladin nodes) to reach
// a state that it can successfully (and anonymously) submitted it to the blockchain.
type PrivateTransaction struct {

	// The identifier for the transaction
	ID      uuid.UUID           `json:"id"`
	Domain  string              `json:"domain"`
	Address pldtypes.EthAddress `json:"address"`

	// This enum describes the point in the private transaction flow where processing of the transaction should stop
	Intent prototk.TransactionSpecification_Intent `json:"intent"`

	// ASSEMBLY PHASE: Items that get added to the transaction as it goes on its journey through
	// assembly, signing and endorsement (possibly going back through the journey many times)
	PreAssembly  *prototk.TransactionPreAssembly `json:"pre_assembly"`  // the bit of the assembly phase state that can be retained across re-assembly
	PostAssembly *TransactionPostAssembly        `json:"post_assembly"` // the bit of the assembly phase state that must be completely discarded on re-assembly

	// DISPATCH PHASE: Once the transaction has reached sufficient confidence of success, we move on to submission.
	// Each private transaction may result in a public transaction which should be submitted to the
	// base ledger, or another private transaction which should go around the transaction loop again.
	Signer                     string                   `json:"signer"`
	PreparedPublicTransaction  *pldapi.TransactionInput `json:"-"`
	PreparedPrivateTransaction *pldapi.TransactionInput `json:"-"`
	PreparedMetadata           pldtypes.RawJSON         `json:"-"`
}

// ToDelegation returns the minimal wire descriptor for this transaction when delegating
// to a coordinator
func (pt *PrivateTransaction) ToDelegation() *prototk.PrivateTransactionDelegation {
	return &prototk.PrivateTransactionDelegation{
		Id:          pt.ID.String(),
		Domain:      pt.Domain,
		Intent:      pt.Intent,
		PreAssembly: pt.PreAssembly,
	}
}

// NewPrivateTransactionFromDelegation reconstructs a PrivateTransaction from a wire
// delegation descriptor
func NewPrivateTransactionFromDelegation(del *prototk.PrivateTransactionDelegation, address pldtypes.EthAddress) *PrivateTransaction {
	id, err := uuid.Parse(del.GetId())
	if err != nil {
		return nil
	}
	return &PrivateTransaction{
		ID:          id,
		Domain:      del.GetDomain(),
		Address:     address,
		Intent:      del.GetIntent(),
		PreAssembly: del.GetPreAssembly(),
	}
}

// CleanUpPostAssemblyData releases the heavy post-assembly and prepared-dispatch
// payload data. Shared by re-assembly cleanup (which retains PreAssembly for reuse)
// and post-dispatch cleanup (which additionally releases PreAssembly).
func (pt *PrivateTransaction) CleanUpPostAssemblyData() {
	pt.PostAssembly = nil
	pt.PreparedPublicTransaction = nil
	pt.PreparedPrivateTransaction = nil
	pt.PreparedMetadata = nil
}

// PrivateContractDeploy is a simpler transaction type that constructs new private smart contract instances
// within a domain, according to the constructor specification of that domain.
type PrivateContractDeploy struct {

	// INPUTS: Items that come in from the submitter of the transaction to send to the constructor
	ID     uuid.UUID
	Domain string
	From   string
	Inputs pldtypes.RawJSON

	// ASSEMBLY PHASE
	TransactionSpecification *prototk.DeployTransactionSpecification
	RequiredVerifiers        []*prototk.ResolveVerifierRequest
	Verifiers                []*prototk.ResolvedVerifier

	// DISPATCH PHASE
	Signer            string
	InvokeTransaction *EthTransaction
	DeployTransaction *EthDeployTransaction
}

type PrivateTransactionEndorseRequest struct {
	BlockContext             *prototk.BlockContext
	TransactionSpecification *prototk.TransactionSpecification
	Verifiers                []*prototk.ResolvedVerifier
	Signatures               []*prototk.AttestationResult
	InputStates              []*prototk.EndorsableState
	ReadStates               []*prototk.EndorsableState
	OutputStates             []*prototk.EndorsableState
	InfoStates               []*prototk.EndorsableState
	Endorsement              *prototk.AttestationRequest
	Endorser                 *prototk.ResolvedVerifier
}
