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

package integrationtest

import (
	"context"
	"testing"

	"github.com/LFDT-Paladin/paladin/common/go/pkg/log"
	"github.com/LFDT-Paladin/paladin/core/pkg/testbed"
	"github.com/LFDT-Paladin/paladin/domains/integration-test/helpers"
	"github.com/LFDT-Paladin/paladin/domains/noto/pkg/types"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldapi"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/query"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/rpcclient"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/algorithms"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/verifiers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// queryContractStatesWithStatus lists a contract's states for a given status qualifier.
// findAvailableCoins is hardcoded to "available"; this test needs "all", so that its
// assertions are about whether the state row exists at all rather than about whether it has
// been confirmed on-chain.
func queryContractStatesWithStatus(t *testing.T, ctx context.Context, rpc rpcclient.Client,
	domainName, coinSchemaID string, address *pldtypes.EthAddress, status pldapi.StateStatusQualifier,
) []*types.NotoCoinState {
	var states []*types.NotoCoinState
	rpcerr := rpc.CallRPC(ctx, &states, "pstate_queryContractStates",
		domainName,
		address,
		coinSchemaID,
		query.NewQueryBuilder().Limit(100).Query(),
		status)
	require.NoError(t, rpcerr)
	return states
}

// TestNotoCrossContractStateIDCollision demonstrates that a Noto coin can be made to
// disappear from the token it was paid into, because state identifiers are not scoped by
// contract. It uses a regular (non-nullifier) Noto token - the flaw is in the state
// identifier itself, so it applies to every variant.
//
// Two ingredients:
//
//  1. A state's id is a hash of the state data only (see abiSchema.ProcessState, which calls
//     eip712.HashStruct over the schema's type set). The contract address is stored in a
//     column alongside it, but is not part of the hash. So the same NotoCoin data in two
//     different Noto contracts produces one identifier.
//
//  2. Every state record table is keyed on (domain_name, id) or (domain_name, state) with no
//     contract column - `states` (migration 000003), plus state_confirm_records,
//     state_spend_records, state_read_records, state_info_records and state_nullifiers
//     (000004). The insert into `states` is OnConflict DoNothing, treating states as
//     immutable.
//
// Together, the second contract's coin is silently discarded and the surviving row keeps the
// first contract's address, so the coin is invisible in the token it belongs to. On-chain both
// tokens are perfectly happy: each contract's own duplicate-commitment check only ever sees
// its own commitment set.
//
// The attack this enables: the salt of an output coin is chosen by the sender's node, so an
// attacker pays a junk coin into token B using salt S and amount V, then settles a real debt
// in token A with the same S and V for the same recipient. Token A's payment is verifiable
// on-chain, the receipt says success - and the recipient's balance in token A never moves.
//
// This test emulates the salt reuse by storing the colliding coin data directly, because a
// salt is only reusable by an attacker running modified domain code. pstate_storeState drives
// WriteReceivedStates, which is the same path a node uses when it receives a distributed
// state, so the storage behaviour under test is the real one.
//
// TO BE FIXED: the assertions below marked "VULNERABILITY" record today's broken behaviour so
// that this test passes on an unfixed tree. Once state identifiers (or the state record keys)
// are scoped by contract, they must be replaced by the expectations in the comment above each
// one - the coin must exist independently in each token.
func (s *notoTestSuite) TestNotoCrossContractStateIDCollision() {
	t := s.T()
	ctx := t.Context()
	log.L(ctx).Infof("TestNotoCrossContractStateIDCollision")

	waitForNoto, notoTestbed := newNotoDomain(t, pldtypes.MustEthAddress(s.factoryAddress))
	done, _, _, _, paladinClient := newTestbed(t, s.hdWalletSeed, map[string]*testbed.TestbedDomain{
		s.domainName: notoTestbed,
	})
	defer done()

	notoDomain := <-waitForNoto

	notoReceipts := make(chan notoReceiptWithTXID)
	subscribeAndSendNotoReceiptsToChannel(t, paladinClient, notoDomain.Name(), notoReceipts)

	recipient1Key, err := paladinClient.PTX().ResolveVerifier(ctx, recipient1Name, algorithms.ECDSA_SECP256K1, verifiers.ETH_ADDRESS)
	require.NoError(t, err)

	// Two regular Noto tokens, in the same domain. Nothing about them is related: different
	// contracts, deployed independently, each with its own commitment set on the base ledger.
	log.L(ctx).Infof("Deploying two instances of Noto")
	tokenA := helpers.DeployNoto(ctx, t, paladinClient, s.domainName, "", notary, nil)
	tokenB := helpers.DeployNoto(ctx, t, paladinClient, s.domainName, "", notary, nil)
	require.NotEqual(t, tokenA.Address.String(), tokenB.Address.String())
	log.L(ctx).Infof("Noto A deployed to %s, Noto B deployed to %s", tokenA.Address, tokenB.Address)

	// The attacker's junk coin: a real, on-chain mint of 1 unit to the victim in token B.
	// In the wild the attacker's node picks this salt; here the domain picks it and we read it
	// back, which is equivalent from the collision's point of view.
	log.L(ctx).Infof("Mint 1 to recipient1 in token B (the attacker's junk coin)")
	rpcerr := paladinClient.CallRPC(ctx, nil, "testbed_invoke", &pldapi.TransactionInput{
		TransactionBase: pldapi.TransactionBase{
			From:     notaryName,
			To:       tokenB.Address,
			Function: "mint",
			Data: toJSON(t, &types.MintParams{
				To:     recipient1Name,
				Amount: pldtypes.Int64ToInt256(1),
			}),
		},
		ABI: types.NotoABI,
	}, false)
	require.NoError(t, rpcerr)
	<-notoReceipts

	junkCoins := findAvailableCoins[types.NotoCoinState](t, ctx, paladinClient, notoDomain.Name(),
		notoDomain.CoinSchemaID(), "pstate_queryContractStates", tokenB.Address, nil)
	require.Len(t, junkCoins, 1)
	junkCoin := junkCoins[0]
	assert.Equal(t, recipient1Key, junkCoin.Data.Owner.String())
	assert.Equal(t, tokenB.Address.String(), junkCoin.ContractAddress.String())

	// Token A holds nothing yet
	require.Empty(t, queryContractStatesWithStatus(t, ctx, paladinClient, notoDomain.Name(),
		notoDomain.CoinSchemaID(), tokenA.Address, pldapi.StateStatusAll))

	// The victim's node now receives the attacker's payment in token A: a coin with exactly the
	// same salt, owner and amount as the junk coin in token B.
	log.L(ctx).Infof("Receiving a coin with identical data in token A (the attacker's payment)")
	var storedInTokenA pldapi.State
	// this step requires the sender using a modified Paladin that re-uses a salt, rather than generating
	// a genuinely random one. Simulating that by calling pstate_storeState directly.
	rpcerr = paladinClient.CallRPC(ctx, &storedInTokenA, "pstate_storeState",
		notoDomain.Name(),
		tokenA.Address,
		notoDomain.CoinSchemaID(),
		pldtypes.RawJSON(toJSON(t, junkCoin.Data)))
	require.NoError(t, rpcerr)

	// Ingredient 1: one identifier for two coins in two different contracts. This is the root
	// cause, and it holds regardless of how the record tables are keyed.
	require.NotEmpty(t, junkCoin.ID.String())
	require.NotEmpty(t, storedInTokenA.ID.String())
	assert.Equal(t, junkCoin.ID.String(), storedInTokenA.ID.String(),
		"the state id is a hash of the coin data only, so it does not distinguish the two tokens")

	// The store call reports success, and the state it returns names token A...
	assert.Equal(t, tokenA.Address.String(), storedInTokenA.ContractAddress.String())

	// VULNERABILITY: ...but the row was never written, because (domain_name, id) already
	// existed for token B and the insert is OnConflict DoNothing. The coin the victim was paid
	// is simply absent from token A - not merely unconfirmed, absent - so no fix to
	// confirmation handling would surface it.
	// AFTER THE FIX: token A must hold its own coin here, with the victim as owner.
	statesInTokenA := queryContractStatesWithStatus(t, ctx, paladinClient, notoDomain.Name(),
		notoDomain.CoinSchemaID(), tokenA.Address, pldapi.StateStatusAll)
	assert.Empty(t, statesInTokenA,
		"VULNERABILITY: token A's copy of the coin was silently discarded")

	// The surviving row still belongs to token B, unchanged
	statesInTokenB := queryContractStatesWithStatus(t, ctx, paladinClient, notoDomain.Name(),
		notoDomain.CoinSchemaID(), tokenB.Address, pldapi.StateStatusAll)
	require.Len(t, statesInTokenB, 1)
	assert.Equal(t, junkCoin.ID.String(), statesInTokenB[0].ID.String())
	assert.Equal(t, tokenB.Address.String(), statesInTokenB[0].ContractAddress.String())

	// And the consequence the victim sees: they hold the junk coin in token B, and nothing in
	// token A, even though token A's payment is on the base ledger and its receipt succeeded.
	// AFTER THE FIX: the balance in token A must reflect the payment.
	balanceInTokenA := tokenA.BalanceOf(ctx, &types.BalanceOfParam{Account: recipient1Name}).SignAndCall(notaryName).Wait()
	assert.Equal(t, "0", balanceInTokenA["totalBalance"].(string),
		"VULNERABILITY: the payment into token A is invisible to its recipient")

	balanceInTokenB := tokenB.BalanceOf(ctx, &types.BalanceOfParam{Account: recipient1Name}).SignAndCall(notaryName).Wait()
	assert.Equal(t, "1", balanceInTokenB["totalBalance"].(string),
		"the junk coin in token B is unaffected")

	// Control: the same coin with a different salt - so a different identifier - stores and
	// lists under token A perfectly well. Without this, the "token A is empty" assertion above
	// could pass for a boring reason (a wrong schema id or status qualifier); with it, the
	// colliding identifier is isolated as the cause, and it also shows the "all" qualifier does
	// list states that no on-chain event has confirmed.
	nonCollidingCoin := junkCoin.Data
	nonCollidingCoin.Salt = pldtypes.RandBytes32()
	var storedControl pldapi.State
	rpcerr = paladinClient.CallRPC(ctx, &storedControl, "pstate_storeState",
		notoDomain.Name(),
		tokenA.Address,
		notoDomain.CoinSchemaID(),
		pldtypes.RawJSON(toJSON(t, nonCollidingCoin)))
	require.NoError(t, rpcerr)
	assert.NotEqual(t, junkCoin.ID.String(), storedControl.ID.String())

	controlStates := queryContractStatesWithStatus(t, ctx, paladinClient, notoDomain.Name(),
		notoDomain.CoinSchemaID(), tokenA.Address, pldapi.StateStatusAll)
	require.Len(t, controlStates, 1, "a coin with a fresh salt is stored and listed under token A")
	assert.Equal(t, storedControl.ID.String(), controlStates[0].ID.String())
	assert.Equal(t, tokenA.Address.String(), controlStates[0].ContractAddress.String())
}
