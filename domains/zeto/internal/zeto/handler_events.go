package zeto

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/LF-Decentralized-Trust-labs/paladin/common/go/pkg/i18n"
	"github.com/LF-Decentralized-Trust-labs/paladin/common/go/pkg/log"
	"github.com/LF-Decentralized-Trust-labs/paladin/domains/zeto/internal/msgs"
	"github.com/LF-Decentralized-Trust-labs/paladin/domains/zeto/internal/zeto/common"
	"github.com/LF-Decentralized-Trust-labs/paladin/domains/zeto/internal/zeto/smt"
	"github.com/LF-Decentralized-Trust-labs/paladin/domains/zeto/pkg/types"
	"github.com/LF-Decentralized-Trust-labs/paladin/sdk/go/pkg/pldtypes"
	"github.com/LF-Decentralized-Trust-labs/paladin/toolkit/pkg/prototk"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/node"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

func (z *Zeto) recordTransactionInfo(ev *prototk.OnChainEvent, txData *types.ZetoTransactionData_V0, res *prototk.HandleEventBatchResponse) {
	res.TransactionsComplete = append(res.TransactionsComplete, &prototk.CompletedTransaction{
		TransactionId: txData.TransactionID.String(),
		Location:      ev.Location,
	})
	for _, state := range txData.InfoStates {
		res.InfoStates = append(res.InfoStates, &prototk.StateUpdate{
			Id:            state.String(),
			TransactionId: txData.TransactionID.String(),
		})
	}
}

func (z *Zeto) handleMintEvent(ctx context.Context, smtTree *common.MerkleTreeSpec, ev *prototk.OnChainEvent, tokenName string, res *prototk.HandleEventBatchResponse) error {
	var mint MintEvent
	if err := json.Unmarshal([]byte(ev.DataJson), &mint); err == nil {
		txData, err := decodeTransactionData(ctx, mint.Data)
		if err != nil || txData == nil {
			log.L(ctx).Errorf("Failed to decode transaction data for mint event: %s. Skip to the next event", mint.Data)
			return nil
		}
		z.recordTransactionInfo(ev, txData, res)
		res.ConfirmedStates = append(res.ConfirmedStates, parseStatesFromEvent(txData.TransactionID, mint.Outputs)...)
		if common.IsNullifiersToken(tokenName) {
			err := z.updateMerkleTree(ctx, smtTree.Tree, smtTree.Storage, txData.TransactionID, mint.Outputs)
			if err != nil {
				return i18n.NewError(ctx, msgs.MsgErrorUpdateSMT, "UTXOMint", err)
			}
		}
	} else {
		log.L(ctx).Errorf("Failed to unmarshal mint event: %s", err)
	}
	return nil
}

func (z *Zeto) handleTransferEvent(ctx context.Context, smtTree *common.MerkleTreeSpec, ev *prototk.OnChainEvent, tokenName string, res *prototk.HandleEventBatchResponse) error {
	var transfer TransferEvent
	if err := json.Unmarshal([]byte(ev.DataJson), &transfer); err == nil {
		txData, err := decodeTransactionData(ctx, transfer.Data)
		if err != nil || txData == nil {
			log.L(ctx).Errorf("Failed to decode transaction data for transfer event: %s. Skip to the next event", transfer.Data)
			return nil
		}
		z.recordTransactionInfo(ev, txData, res)
		res.SpentStates = append(res.SpentStates, parseStatesFromEvent(txData.TransactionID, transfer.Inputs)...)
		res.ConfirmedStates = append(res.ConfirmedStates, parseStatesFromEvent(txData.TransactionID, transfer.Outputs)...)
		if common.IsNullifiersToken(tokenName) {
			err := z.updateMerkleTree(ctx, smtTree.Tree, smtTree.Storage, txData.TransactionID, transfer.Outputs)
			if err != nil {
				return i18n.NewError(ctx, msgs.MsgErrorUpdateSMT, "UTXOTransfer", err)
			}
		}
	} else {
		log.L(ctx).Errorf("Failed to unmarshal transfer event: %s", err)
	}
	return nil
}

func (z *Zeto) handleTransferWithEncryptionEvent(ctx context.Context, smtTree *common.MerkleTreeSpec, ev *prototk.OnChainEvent, tokenName string, res *prototk.HandleEventBatchResponse) error {
	var transfer TransferWithEncryptedValuesEvent
	if err := json.Unmarshal([]byte(ev.DataJson), &transfer); err == nil {
		txData, err := decodeTransactionData(ctx, transfer.Data)
		if err != nil || txData == nil {
			log.L(ctx).Errorf("Failed to decode transaction data for transfer event: %s. Skip to the next event", transfer.Data)
			return nil
		}
		z.recordTransactionInfo(ev, txData, res)
		res.SpentStates = append(res.SpentStates, parseStatesFromEvent(txData.TransactionID, transfer.Inputs)...)
		res.ConfirmedStates = append(res.ConfirmedStates, parseStatesFromEvent(txData.TransactionID, transfer.Outputs)...)
		if common.IsNullifiersToken(tokenName) {
			err := z.updateMerkleTree(ctx, smtTree.Tree, smtTree.Storage, txData.TransactionID, transfer.Outputs)
			if err != nil {
				return i18n.NewError(ctx, msgs.MsgErrorUpdateSMT, "UTXOTransferWithEncryptedValues", err)
			}
		}
	} else {
		log.L(ctx).Errorf("Failed to unmarshal transfer event: %s", err)
	}
	return nil
}

func (z *Zeto) handleWithdrawEvent(ctx context.Context, smtTree *common.MerkleTreeSpec, ev *prototk.OnChainEvent, tokenName string, res *prototk.HandleEventBatchResponse) error {
	var withdraw WithdrawEvent
	if err := json.Unmarshal([]byte(ev.DataJson), &withdraw); err == nil {
		txData, err := decodeTransactionData(ctx, withdraw.Data)
		if err != nil || txData == nil {
			log.L(ctx).Errorf("Failed to decode transaction data for withdraw event: %s. Skip to the next event", withdraw.Data)
			return nil
		}
		z.recordTransactionInfo(ev, txData, res)
		res.SpentStates = append(res.SpentStates, parseStatesFromEvent(txData.TransactionID, withdraw.Inputs)...)
		res.ConfirmedStates = append(res.ConfirmedStates, parseStatesFromEvent(txData.TransactionID, []pldtypes.HexUint256{withdraw.Output})...)
		if common.IsNullifiersToken(tokenName) {
			err := z.updateMerkleTree(ctx, smtTree.Tree, smtTree.Storage, txData.TransactionID, []pldtypes.HexUint256{withdraw.Output})
			if err != nil {
				return i18n.NewError(ctx, msgs.MsgErrorUpdateSMT, "UTXOWithdraw", err)
			}
		}
	} else {
		log.L(ctx).Errorf("Failed to unmarshal withdraw event: %s", err)
	}
	return nil
}

func (z *Zeto) handleLockedEvent(ctx context.Context, smtTree *common.MerkleTreeSpec, smtTreeForLocked *common.MerkleTreeSpec, ev *prototk.OnChainEvent, tokenName string, res *prototk.HandleEventBatchResponse) error {
	var lock LockedEvent
	if err := json.Unmarshal([]byte(ev.DataJson), &lock); err == nil {
		txData, err := decodeTransactionData(ctx, lock.Data)
		if err != nil || txData == nil {
			log.L(ctx).Errorf("Failed to decode transaction data for lock event: %s. Skip to the next event", lock.Data)
			return nil
		}
		z.recordTransactionInfo(ev, txData, res)
		res.SpentStates = append(res.SpentStates, parseStatesFromEvent(txData.TransactionID, lock.Inputs)...)
		res.ConfirmedStates = append(res.ConfirmedStates, parseStatesFromEvent(txData.TransactionID, lock.Outputs)...)
		res.ConfirmedStates = append(res.ConfirmedStates, parseStatesFromEvent(txData.TransactionID, lock.LockedOutputs)...)
		if common.IsNullifiersToken(tokenName) {
			err := z.updateMerkleTree(ctx, smtTree.Tree, smtTree.Storage, txData.TransactionID, lock.Outputs)
			if err != nil {
				return i18n.NewError(ctx, msgs.MsgErrorUpdateSMT, "UTXOsLocked", err)
			}
			err = z.updateMerkleTree(ctx, smtTreeForLocked.Tree, smtTreeForLocked.Storage, txData.TransactionID, lock.LockedOutputs)
			if err != nil {
				return i18n.NewError(ctx, msgs.MsgErrorUpdateSMT, "UTXOsLocked", err)
			}
		}
	} else {
		log.L(ctx).Errorf("Failed to unmarshal lock event: %s", err)
	}
	return nil
}

func (z *Zeto) handleIdentityRegisteredEvent(ctx context.Context, smtKycTree *common.MerkleTreeSpec, ev *prototk.OnChainEvent, tokenName string, res *prototk.HandleEventBatchResponse) error {
	var registered IdentityRegisteredEvent
	if err := json.Unmarshal([]byte(ev.DataJson), &registered); err == nil {
		txData, err := decodeTransactionData(ctx, registered.Data)
		if err != nil || txData == nil {
			txId := pldtypes.MustParseBytes32("0000000000000000000000000000000000000000000000000000000000000000")
			log.L(ctx).Infof("IdentityRegistered event [publicKey=%+v] has no tx data. Inserting zero tx ID", &registered.PublicKey)
			txData = &types.ZetoTransactionData_V0{
				TransactionID: txId,
				InfoStates:    []pldtypes.Bytes32{},
			}
		}
		if common.IsKycToken(tokenName) {
			// calculate the Poseidon hash of the public key, to use as the leaf node index and value in the SMT
			publicKeyHash, err := poseidon.Hash([]*big.Int{registered.PublicKey[0].Int(), registered.PublicKey[1].Int()})
			if err != nil {
				return i18n.NewError(ctx, msgs.MsgErrorHandleEvents, fmt.Sprintf("IdentityRegistered. %s", err))
			}
			err = z.updateMerkleTree(ctx, smtKycTree.Tree, smtKycTree.Storage, txData.TransactionID, []pldtypes.HexUint256{*pldtypes.MustParseHexUint256("0x" + publicKeyHash.Text(16))})
			if err != nil {
				// Check if this is a "key already exists" error - if so, treat it as success for idempotency
				if strings.Contains(err.Error(), "key already exists") || strings.Contains(err.Error(), "already exists") {
					log.L(ctx).Infof("Identity with publicKey=%+v is already registered in KYC tree - treating as success", &registered.PublicKey)
				} else {
					return i18n.NewError(ctx, msgs.MsgErrorUpdateSMT, "IdentityRegistered", err)
				}
			}
		}
	} else {
		log.L(ctx).Errorf("Failed to unmarshal IdentityRegistered event: %s", err)
	}
	return nil
}

func (z *Zeto) updateMerkleTree(ctx context.Context, tree core.SparseMerkleTree, storage smt.StatesStorage, txID pldtypes.Bytes32, outputs []pldtypes.HexUint256) error {
	storage.SetTransactionId(txID.HexString0xPrefix())
	for _, out := range outputs {
		if out.NilOrZero() {
			continue
		}
		err := z.addOutputToMerkleTree(ctx, tree, out)
		if err != nil {
			return err
		}
	}
	return nil
}

func (z *Zeto) addOutputToMerkleTree(ctx context.Context, tree core.SparseMerkleTree, output pldtypes.HexUint256) error {
	idx, err := node.NewNodeIndexFromBigInt(output.Int())
	if err != nil {
		return i18n.NewError(ctx, msgs.MsgErrorNewNodeIndex, output.String(), err)
	}
	n := node.NewIndexOnly(idx)
	leaf, err := node.NewLeafNode(n)
	if err != nil {
		return i18n.NewError(ctx, msgs.MsgErrorNewLeafNode, err)
	}
	err = tree.AddLeaf(leaf)
	if err != nil {
		return i18n.NewError(ctx, msgs.MsgErrorAddLeafNode, err)
	}
	return nil
}

func parseStatesFromEvent(txID pldtypes.Bytes32, states []pldtypes.HexUint256) []*prototk.StateUpdate {
	refs := make([]*prototk.StateUpdate, len(states))
	for i, state := range states {
		refs[i] = &prototk.StateUpdate{
			Id:            common.HexUint256To32ByteHexString(&state),
			TransactionId: txID.String(),
		}
	}
	return refs
}

func formatErrors(errors []string) string {
	msg := fmt.Sprintf("(failures=%d)", len(errors))
	for i, err := range errors {
		msg = fmt.Sprintf("%s. [%d]%s", msg, i, err)
	}
	return msg
}

func decodeTransactionData(ctx context.Context, data pldtypes.HexBytes) (*types.ZetoTransactionData_V0, error) {
	if len(data) < 4 {
		return nil, nil
	}
	dataPrefix := data[0:4]
	if dataPrefix.String() != types.ZetoTransactionDataID_V0.String() {
		return nil, nil
	}

	var dataValues types.ZetoTransactionData_V0
	dataDecoded, err := types.ZetoTransactionDataABI_V0.DecodeABIDataCtx(ctx, data, 4)
	if err == nil {
		var dataJSON []byte
		dataJSON, err = dataDecoded.JSON()
		if err == nil {
			err = json.Unmarshal(dataJSON, &dataValues)
		}
	}
	if err != nil {
		return nil, err
	}
	return &dataValues, nil
}
