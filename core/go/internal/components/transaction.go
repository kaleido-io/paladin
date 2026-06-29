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

type TransactionPostAssembly struct {
	AssemblyResult        prototk.AssembleTransactionResponse_Result `json:"assembly_result"`
	OutputStatesPotential []*prototk.NewState                        `json:"output_states_potential"` // the raw result of assembly, before sequence allocation
	InfoStatesPotential   []*prototk.NewState                        `json:"info_states_potential"`   // the raw result of assembly, before sequence allocation
	InputStates           []*FullState                               `json:"input_states"`
	ReadStates            []*FullState                               `json:"read_states"`
	OutputStates          []*FullState                               `json:"output_states"`
	InfoStates            []*FullState                               `json:"info_states"`
	AttestationPlan       []*prototk.AttestationRequest              `json:"attestation_plan"`
	Signatures            []*prototk.AttestationResult               `json:"signatures"`
	Endorsements          []*prototk.AttestationResult               `json:"endorsements"`
	DomainData            *string                                    `json:"domain_data"`
	RevertReason          *string                                    `json:"revert_reason"`
	ResolvedVerifiers     []*prototk.ResolvedVerifier                `json:"resolved_verifiers"`
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
// to a coordinator. The contract address is carried at the DelegationRequest level (all
// transactions in one request share the same contract), so it is not repeated here.
// PostAssembly is deliberately excluded — the coordinator always triggers fresh assembly.
func (pt *PrivateTransaction) ToDelegation() *prototk.PrivateTransactionDelegation {
	return &prototk.PrivateTransactionDelegation{
		Id:          pt.ID.String(),
		Domain:      pt.Domain,
		Intent:      pt.Intent,
		PreAssembly: pt.PreAssembly,
	}
}

// NewPrivateTransactionFromDelegation reconstructs a PrivateTransaction from a wire
// delegation descriptor. The contract address is sourced from the enclosing DelegationRequest
// (shared by all transactions) and passed in directly. Returns nil if the ID cannot be parsed.
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
