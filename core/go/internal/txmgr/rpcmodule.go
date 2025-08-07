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

package txmgr

import (
	"context"

	"github.com/LF-Decentralized-Trust-labs/paladin/core/internal/components"
	"github.com/LF-Decentralized-Trust-labs/paladin/sdk/go/pkg/pldapi"
	"github.com/LF-Decentralized-Trust-labs/paladin/sdk/go/pkg/pldtypes"
	"github.com/LF-Decentralized-Trust-labs/paladin/sdk/go/pkg/query"
	"github.com/LF-Decentralized-Trust-labs/paladin/toolkit/pkg/rpcserver"
	"github.com/google/uuid"
	"github.com/hyperledger/firefly-signer/pkg/abi"
)

func (tm *txManager) buildRPCModule() {
	tm.rpcModule = rpcserver.NewRPCModule("ptx").
		Add("ptx_sendTransaction", tm.rpcSendTransaction()).
		Add("ptx_sendTransactions", tm.rpcSendTransactions()).
		Add("ptx_prepareTransaction", tm.rpcPrepareTransaction()).
		Add("ptx_prepareTransactions", tm.rpcPrepareTransactions()).
		Add("ptx_updateTransaction", tm.rpcUpdateTransaction()).
		Add("ptx_call", tm.rpcCall()).
		Add("ptx_getTransaction", tm.rpcGetTransaction()).
		Add("ptx_getTransactionFull", tm.rpcGetTransactionFull()).
		Add("ptx_getTransactionByIdempotencyKey", tm.rpcGetTransactionByIdempotencyKey()).
		Add("ptx_queryTransactions", tm.rpcQueryTransactions()).
		Add("ptx_queryTransactionsFull", tm.rpcQueryTransactionsFull()).
		Add("ptx_queryPendingTransactions", tm.rpcQueryPendingTransactions()).
		Add("ptx_getTransactionReceipt", tm.rpcGetTransactionReceipt()).
		Add("ptx_getTransactionReceiptFull", tm.rpcGetTransactionReceiptFull()).
		Add("ptx_getDomainReceipt", tm.rpcGetDomainReceipt()).
		Add("ptx_getStateReceipt", tm.rpcGetStateReceipt()).
		Add("ptx_queryTransactionReceipts", tm.rpcQueryTransactionReceipts()).
		Add("ptx_getTransactionDependencies", tm.rpcGetTransactionDependencies()).
		Add("ptx_queryPublicTransactions", tm.rpcQueryPublicTransactions()).
		Add("ptx_queryPendingPublicTransactions", tm.rpcQueryPendingPublicTransactions()).
		Add("ptx_getPublicTransactionByNonce", tm.rpcGetPublicTransactionByNonce()).
		Add("ptx_getPublicTransactionByHash", tm.rpcGetPublicTransactionByHash()).
		Add("ptx_getPreparedTransaction", tm.rpcGetPreparedTransaction()).
		Add("ptx_queryPreparedTransactions", tm.rpcQueryPreparedTransactions()).
		Add("ptx_storeABI", tm.rpcStoreABI()).
		Add("ptx_getStoredABI", tm.rpcGetStoredABI()).
		Add("ptx_queryStoredABIs", tm.rpcQueryStoredABIs()).
		Add("ptx_decodeCall", tm.rpcDecodeCall()).
		Add("ptx_decodeEvent", tm.rpcDecodeEvent()).
		Add("ptx_decodeError", tm.rpcDecodeError()).
		Add("ptx_resolveVerifier", tm.rpcResolveVerifier()).
		Add("ptx_createReceiptListener", tm.rpcCreateReceiptListener()).
		Add("ptx_queryReceiptListeners", tm.rpcQueryReceiptListeners()).
		Add("ptx_getReceiptListener", tm.rpcGetReceiptListener()).
		Add("ptx_startReceiptListener", tm.rpcStartReceiptListener()).
		Add("ptx_stopReceiptListener", tm.rpcStopReceiptListener()).
		Add("ptx_deleteReceiptListener", tm.rpcDeleteReceiptListener()).
		Add("ptx_createBlockchainEventListener", tm.rpcCreateBlockchainEventListener()).
		Add("ptx_queryBlockchainEventListeners", tm.rpcQueryBlockchainEventListeners()).
		Add("ptx_getBlockchainEventListener", tm.rpcGetBlockchainEventListener()).
		Add("ptx_startBlockchainEventListener", tm.rpcStartBlockchainEventListener()).
		Add("ptx_stopBlockchainEventListener", tm.rpcStopBlockchainEventListener()).
		Add("ptx_deleteBlockchainEventListener", tm.rpcDeleteBlockchainEventListener()).
		Add("ptx_getBlockchainEventListenerStatus", tm.rpcGetBlockchainEventListenerStatus()).
		AddAsync(tm.rpcEventStreams)

	tm.debugRpcModule = rpcserver.NewRPCModule("debug").
		Add("debug_getTransactionStatus", tm.rpcDebugTransactionStatus())
}

func (tm *txManager) rpcSendTransaction() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		tx pldapi.TransactionInput,
	) (*uuid.UUID, error) {
		tm.metrics.IncRpc("sendTransaction")
		return tm.sendTransactionNewDBTX(ctx, &tx)
	})
}

func (tm *txManager) rpcSendTransactions() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		txs []*pldapi.TransactionInput,
	) ([]uuid.UUID, error) {
		tm.metrics.IncRpc("sendTransactions")
		return tm.sendTransactionsNewDBTX(ctx, txs)
	})
}

func (tm *txManager) rpcPrepareTransaction() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		tx pldapi.TransactionInput,
	) (*uuid.UUID, error) {
		tm.metrics.IncRpc("prepareTransaction")
		return tm.prepareTransactionNewDBTX(ctx, &tx)
	})
}

func (tm *txManager) rpcPrepareTransactions() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		txs []*pldapi.TransactionInput,
	) ([]uuid.UUID, error) {
		tm.metrics.IncRpc("prepareTransactions")
		return tm.prepareTransactionsNewDBTX(ctx, txs)
	})
}

func (tm *txManager) rpcUpdateTransaction() rpcserver.RPCHandler {
	return rpcserver.RPCMethod2(func(ctx context.Context,
		id uuid.UUID,
		tx *pldapi.TransactionInput,
	) (uuid.UUID, error) {
		tm.metrics.IncRpc("updateTransaction")
		return tm.UpdateTransaction(ctx, id, tx)
	})
}

func (tm *txManager) rpcCall() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		tx *pldapi.TransactionCall,
	) (result pldtypes.RawJSON, err error) {
		tm.metrics.IncRpc("call")
		err = tm.CallTransaction(ctx, tm.p.NOTX(), &result, tx)
		return
	})
}

func (tm *txManager) rpcGetTransaction() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		id uuid.UUID,
	) (*pldapi.Transaction, error) {
		tm.metrics.IncRpc("getTransaction")
		return tm.GetTransactionByID(ctx, id)
	})
}

func (tm *txManager) rpcGetTransactionFull() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		id uuid.UUID,
	) (*pldapi.TransactionFull, error) {
		tm.metrics.IncRpc("getTransactionFull")
		return tm.GetTransactionByIDFull(ctx, id)
	})
}

func (tm *txManager) rpcGetTransactionByIdempotencyKey() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		idempotencyKey string,
	) (*pldapi.Transaction, error) {
		tm.metrics.IncRpc("getTransactionByIdempotencyKey")
		return tm.GetTransactionByIdempotencyKey(ctx, idempotencyKey)
	})
}

func (tm *txManager) rpcQueryTransactions() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		query query.QueryJSON,
	) ([]*pldapi.Transaction, error) {
		tm.metrics.IncRpc("queryTransactions")
		return tm.QueryTransactions(ctx, &query, tm.p.NOTX(), false)
	})
}

func (tm *txManager) rpcQueryTransactionsFull() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		query query.QueryJSON,
	) ([]*pldapi.TransactionFull, error) {
		tm.metrics.IncRpc("queryTransactionsFull")
		return tm.QueryTransactionsFull(ctx, &query, tm.p.NOTX(), false)
	})
}

func (tm *txManager) rpcQueryPendingTransactions() rpcserver.RPCHandler {
	return rpcserver.RPCMethod2(func(ctx context.Context,
		query query.QueryJSON,
		full bool,
	) (any, error) {
		if full {
			tm.metrics.IncRpc("queryPendingTransactionsFull")
			return tm.QueryTransactionsFull(ctx, &query, tm.p.NOTX(), true)
		}
		tm.metrics.IncRpc("queryPendingTransactions")
		return tm.QueryTransactions(ctx, &query, tm.p.NOTX(), true)
	})
}

func (tm *txManager) rpcGetTransactionReceipt() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		id uuid.UUID,
	) (*pldapi.TransactionReceipt, error) {
		tm.metrics.IncRpc("getTransactionReceipt")
		return tm.GetTransactionReceiptByID(ctx, id)
	})
}

func (tm *txManager) rpcGetTransactionReceiptFull() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		id uuid.UUID,
	) (*pldapi.TransactionReceiptFull, error) {
		tm.metrics.IncRpc("getTransactionReceiptFull")
		return tm.GetTransactionReceiptByIDFull(ctx, id)
	})
}

func (tm *txManager) rpcGetPreparedTransaction() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		id uuid.UUID,
	) (*pldapi.PreparedTransaction, error) {
		tm.metrics.IncRpc("getPreparedTransaction")
		return tm.GetPreparedTransactionByID(ctx, tm.p.NOTX(), id)
	})
}

func (tm *txManager) rpcGetDomainReceipt() rpcserver.RPCHandler {
	return rpcserver.RPCMethod2(func(ctx context.Context,
		domain string,
		id uuid.UUID,
	) (pldtypes.RawJSON, error) {
		tm.metrics.IncRpc("getDomainReceipt")
		return tm.GetDomainReceiptByID(ctx, domain, id)
	})
}

func (tm *txManager) rpcGetStateReceipt() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		id uuid.UUID,
	) (*pldapi.TransactionStates, error) {
		tm.metrics.IncRpc("getStateReceipt")
		return tm.GetStateReceiptByID(ctx, id)
	})
}

func (tm *txManager) rpcGetTransactionDependencies() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		id uuid.UUID,
	) (*pldapi.TransactionDependencies, error) {
		tm.metrics.IncRpc("getTransactionDependencies")
		return tm.GetTransactionDependencies(ctx, id)
	})
}

func (tm *txManager) rpcQueryTransactionReceipts() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		query query.QueryJSON,
	) ([]*pldapi.TransactionReceipt, error) {
		tm.metrics.IncRpc("queryTransactionReceipts")
		return tm.QueryTransactionReceipts(ctx, &query)
	})
}

func (tm *txManager) rpcQueryPreparedTransactions() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		query query.QueryJSON,
	) ([]*pldapi.PreparedTransaction, error) {
		tm.metrics.IncRpc("queryPreparedTransactions")
		return tm.QueryPreparedTransactions(ctx, tm.p.NOTX(), &query)
	})
}

func (tm *txManager) rpcQueryPublicTransactions() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		query query.QueryJSON,
	) ([]*pldapi.PublicTxWithBinding, error) {
		tm.metrics.IncRpc("queryPublicTransactions")
		return tm.queryPublicTransactions(ctx, &query)
	})
}

func (tm *txManager) rpcQueryPendingPublicTransactions() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		query query.QueryJSON,
	) ([]*pldapi.PublicTxWithBinding, error) {
		tm.metrics.IncRpc("queryPendingPublicTransactions")
		return tm.queryPublicTransactions(ctx, query.ToBuilder().Null("transactionHash").Query())
	})
}

func (tm *txManager) rpcGetPublicTransactionByNonce() rpcserver.RPCHandler {
	return rpcserver.RPCMethod2(func(ctx context.Context,
		from pldtypes.EthAddress,
		nonce pldtypes.HexUint64,
	) (*pldapi.PublicTxWithBinding, error) {
		tm.metrics.IncRpc("getPublicTransactionByNonce")
		return tm.GetPublicTransactionByNonce(ctx, from, nonce)
	})
}

func (tm *txManager) rpcGetPublicTransactionByHash() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		hash pldtypes.Bytes32,
	) (*pldapi.PublicTxWithBinding, error) {
		tm.metrics.IncRpc("getPublicTransactionByHash")
		return tm.GetPublicTransactionByHash(ctx, hash)
	})
}

func (tm *txManager) rpcStoreABI() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		a abi.ABI,
	) (hash *pldtypes.Bytes32, err error) {
		tm.metrics.IncRpc("storeABI")
		return tm.storeABINewDBTX(ctx, a)
	})
}

func (tm *txManager) rpcGetStoredABI() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		hash pldtypes.Bytes32,
	) (*pldapi.StoredABI, error) {
		tm.metrics.IncRpc("getStoredABI")
		return tm.getABIByHash(ctx, tm.p.NOTX(), hash)
	})
}

func (tm *txManager) rpcQueryStoredABIs() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		query query.QueryJSON,
	) ([]*pldapi.StoredABI, error) {
		tm.metrics.IncRpc("queryStoredABIs")
		return tm.queryABIs(ctx, &query)
	})
}

func (tm *txManager) rpcResolveVerifier() rpcserver.RPCHandler {
	return rpcserver.RPCMethod3(func(ctx context.Context,
		lookup string,
		algorithm string,
		verifierType string,
	) (string, error) {
		tm.metrics.IncRpc("resolveVerifier")
		return tm.identityResolver.ResolveVerifier(ctx, lookup, algorithm, verifierType)
	})
}

func (tm *txManager) rpcDebugTransactionStatus() rpcserver.RPCHandler {
	return rpcserver.RPCMethod2(func(ctx context.Context,
		contractAddress string,
		id uuid.UUID,
	) (components.PrivateTxStatus, error) {
		tm.metrics.IncRpc("debugTransactionStatus")
		return tm.privateTxMgr.GetTxStatus(ctx, contractAddress, id)
	})
}

func (tm *txManager) rpcDecodeError() rpcserver.RPCHandler {
	return rpcserver.RPCMethod2(func(ctx context.Context,
		revertError pldtypes.HexBytes,
		dataFormat pldtypes.JSONFormatOptions,
	) (*pldapi.ABIDecodedData, error) {
		tm.metrics.IncRpc("decodeError")
		return tm.DecodeRevertError(ctx, tm.p.NOTX(), revertError, dataFormat)
	})
}

func (tm *txManager) rpcDecodeCall() rpcserver.RPCHandler {
	return rpcserver.RPCMethod2(func(ctx context.Context,
		callData pldtypes.HexBytes,
		dataFormat pldtypes.JSONFormatOptions,
	) (*pldapi.ABIDecodedData, error) {
		tm.metrics.IncRpc("decodeCall")
		return tm.DecodeCall(ctx, tm.p.NOTX(), callData, dataFormat)
	})
}

func (tm *txManager) rpcDecodeEvent() rpcserver.RPCHandler {
	return rpcserver.RPCMethod3(func(ctx context.Context,
		topics []pldtypes.Bytes32,
		data pldtypes.HexBytes,
		dataFormat pldtypes.JSONFormatOptions,
	) (*pldapi.ABIDecodedData, error) {
		tm.metrics.IncRpc("decodeEvent")
		return tm.DecodeEvent(ctx, tm.p.NOTX(), topics, data, dataFormat)
	})
}

func (tm *txManager) rpcCreateReceiptListener() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		listener *pldapi.TransactionReceiptListener,
	) (bool, error) {
		tm.metrics.IncRpc("createReceiptListener")
		err := tm.CreateReceiptListener(ctx, listener)
		return err == nil, err
	})
}

func (tm *txManager) rpcQueryReceiptListeners() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		query query.QueryJSON,
	) ([]*pldapi.TransactionReceiptListener, error) {
		tm.metrics.IncRpc("queryReceiptListeners")
		return tm.QueryReceiptListeners(ctx, tm.p.NOTX(), &query)
	})
}

func (tm *txManager) rpcGetReceiptListener() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		name string,
	) (*pldapi.TransactionReceiptListener, error) {
		tm.metrics.IncRpc("getReceiptListener")
		return tm.GetReceiptListener(ctx, name), nil
	})
}

func (tm *txManager) rpcStartReceiptListener() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		name string,
	) (bool, error) {
		tm.metrics.IncRpc("startReceiptListener")
		return true, tm.StartReceiptListener(ctx, name)
	})
}

func (tm *txManager) rpcStopReceiptListener() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		name string,
	) (bool, error) {
		tm.metrics.IncRpc("stopReceiptListener")
		return true, tm.StopReceiptListener(ctx, name)
	})
}

func (tm *txManager) rpcDeleteReceiptListener() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		name string,
	) (bool, error) {
		tm.metrics.IncRpc("deleteReceiptListener")
		return true, tm.DeleteReceiptListener(ctx, name)
	})
}

func (tm *txManager) rpcCreateBlockchainEventListener() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		listener *pldapi.BlockchainEventListener,
	) (bool, error) {
		tm.metrics.IncRpc("createBlockchainEventListener")
		err := tm.CreateBlockchainEventListener(ctx, listener)
		return err == nil, err
	})
}

func (tm *txManager) rpcQueryBlockchainEventListeners() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		query query.QueryJSON,
	) ([]*pldapi.BlockchainEventListener, error) {
		tm.metrics.IncRpc("queryBlockchainEventListeners")
		return tm.QueryBlockchainEventListeners(ctx, tm.p.NOTX(), &query)
	})
}

func (tm *txManager) rpcGetBlockchainEventListener() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		name string,
	) (*pldapi.BlockchainEventListener, error) {
		tm.metrics.IncRpc("getBlockchainEventListener")
		return tm.GetBlockchainEventListener(ctx, name), nil
	})
}

func (tm *txManager) rpcStartBlockchainEventListener() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		name string,
	) (bool, error) {
		tm.metrics.IncRpc("startBlockchainEventListener")
		return true, tm.StartBlockchainEventListener(ctx, name)
	})
}

func (tm *txManager) rpcStopBlockchainEventListener() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		name string,
	) (bool, error) {
		tm.metrics.IncRpc("stopBlockchainEventListener")
		return true, tm.StopBlockchainEventListener(ctx, name)
	})
}

func (tm *txManager) rpcDeleteBlockchainEventListener() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		name string,
	) (bool, error) {
		tm.metrics.IncRpc("deleteBlockchainEventListener")
		return true, tm.DeleteBlockchainEventListener(ctx, name)
	})
}

func (tm *txManager) rpcGetBlockchainEventListenerStatus() rpcserver.RPCHandler {
	return rpcserver.RPCMethod1(func(ctx context.Context,
		name string,
	) (*pldapi.BlockchainEventListenerStatus, error) {
		tm.metrics.IncRpc("getBlockchainEventListenerStatus")
		return tm.GetBlockchainEventListenerStatus(ctx, name)
	})
}
