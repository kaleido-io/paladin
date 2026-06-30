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

package components

import (
	"testing"

	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldapi"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/LFDT-Paladin/paladin/toolkit/pkg/prototk"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReleasePostAssemblyData(t *testing.T) {
	pt := &PrivateTransaction{
		ID:      uuid.New(),
		Domain:  "test-domain",
		Address: *pldtypes.RandAddress(),
		Signer:  "signer@node1",
		PreAssembly: &prototk.TransactionPreAssembly{
			TransactionSpecification: &prototk.TransactionSpecification{},
		},
		PostAssembly: &TransactionPostAssembly{
			OutputStates: []*FullState{{Data: pldtypes.RawJSON(`{}`)}},
		},
		PreparedPublicTransaction:  &pldapi.TransactionInput{},
		PreparedPrivateTransaction: &pldapi.TransactionInput{},
		PreparedMetadata:           pldtypes.RawJSON(`{"meta":true}`),
	}

	savedID := pt.ID
	savedDomain := pt.Domain
	savedAddress := pt.Address
	savedSigner := pt.Signer

	pt.CleanUpPostAssemblyData()

	assert.Nil(t, pt.PostAssembly)
	assert.Nil(t, pt.PreparedPublicTransaction)
	assert.Nil(t, pt.PreparedPrivateTransaction)
	assert.Nil(t, pt.PreparedMetadata)

	assert.NotNil(t, pt.PreAssembly, "PreAssembly should be preserved")
	assert.Equal(t, savedID, pt.ID)
	assert.Equal(t, savedDomain, pt.Domain)
	assert.Equal(t, savedAddress, pt.Address)
	assert.Equal(t, savedSigner, pt.Signer)
}

func TestReleasePostAssemblyData_NilFields(t *testing.T) {
	pt := &PrivateTransaction{ID: uuid.New()}
	pt.CleanUpPostAssemblyData()

	assert.Nil(t, pt.PostAssembly)
	assert.Nil(t, pt.PreparedPublicTransaction)
}

func TestToDelegation(t *testing.T) {
	id := uuid.New()
	preAssembly := &prototk.TransactionPreAssembly{
		TransactionSpecification: &prototk.TransactionSpecification{From: "signer@node1"},
	}
	pt := &PrivateTransaction{
		ID:          id,
		Domain:      "test-domain",
		Intent:      prototk.TransactionSpecification_SEND_TRANSACTION,
		PreAssembly: preAssembly,
	}

	del := pt.ToDelegation()

	assert.Equal(t, id.String(), del.Id)
	assert.Equal(t, "test-domain", del.Domain)
	assert.Equal(t, prototk.TransactionSpecification_SEND_TRANSACTION, del.Intent)
	assert.Same(t, preAssembly, del.PreAssembly)
}

func TestNewPrivateTransactionFromDelegation_Success(t *testing.T) {
	id := uuid.New()
	address := *pldtypes.RandAddress()
	preAssembly := &prototk.TransactionPreAssembly{
		TransactionSpecification: &prototk.TransactionSpecification{},
	}
	del := &prototk.PrivateTransactionDelegation{
		Id:          id.String(),
		Domain:      "test-domain",
		Intent:      prototk.TransactionSpecification_SEND_TRANSACTION,
		PreAssembly: preAssembly,
	}

	pt := NewPrivateTransactionFromDelegation(del, address)

	require.NotNil(t, pt)
	assert.Equal(t, id, pt.ID)
	assert.Equal(t, "test-domain", pt.Domain)
	assert.Equal(t, address, pt.Address)
	assert.Equal(t, prototk.TransactionSpecification_SEND_TRANSACTION, pt.Intent)
	assert.Same(t, preAssembly, pt.PreAssembly)
}

func TestNewPrivateTransactionFromDelegation_InvalidID(t *testing.T) {
	del := &prototk.PrivateTransactionDelegation{Id: "not-a-uuid"}
	pt := NewPrivateTransactionFromDelegation(del, *pldtypes.RandAddress())
	assert.Nil(t, pt)
}

func TestFullStatesToEndorsable_Empty(t *testing.T) {
	result := FullStatesToEndorsable(nil)
	assert.Empty(t, result)
}

func TestFullStatesToEndorsable_WithStates(t *testing.T) {
	id := pldtypes.HexBytes(pldtypes.RandBytes(32))
	schema := pldtypes.RandBytes32()
	states := []*FullState{
		{ID: id, Schema: schema, Data: pldtypes.RawJSON(`{"k":"v"}`)},
	}

	result := FullStatesToEndorsable(states)

	require.Len(t, result, 1)
	assert.Equal(t, id.String(), result[0].Id)
	assert.Equal(t, schema.String(), result[0].SchemaId)
	assert.Equal(t, `{"k":"v"}`, result[0].StateDataJson)
}

func TestEndorsableOutputStates_LazyConversion(t *testing.T) {
	id := pldtypes.HexBytes(pldtypes.RandBytes(32))
	schema := pldtypes.RandBytes32()
	pa := &TransactionPostAssembly{
		OutputStates: []*FullState{{ID: id, Schema: schema, Data: pldtypes.RawJSON(`{}`)}},
	}

	first := pa.EndorsableOutputStates()
	require.Len(t, first, 1)
	assert.Equal(t, id.String(), first[0].Id)

	// Second call returns the cached slice
	assert.Same(t, &first[0], &pa.EndorsableOutputStates()[0])
}

func TestEndorsableInfoStates_LazyConversion(t *testing.T) {
	id := pldtypes.HexBytes(pldtypes.RandBytes(32))
	schema := pldtypes.RandBytes32()
	pa := &TransactionPostAssembly{
		InfoStates: []*FullState{{ID: id, Schema: schema, Data: pldtypes.RawJSON(`{}`)}},
	}

	first := pa.EndorsableInfoStates()
	require.Len(t, first, 1)
	assert.Equal(t, id.String(), first[0].Id)

	// Second call returns the cached slice
	assert.Same(t, &first[0], &pa.EndorsableInfoStates()[0])
}
