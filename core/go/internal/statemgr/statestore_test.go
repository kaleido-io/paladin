// Copyright © 2024 Kaleido, Inc.
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
	"context"
	"fmt"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/LFDT-Paladin/paladin/common/go/pkg/log"
	"github.com/LFDT-Paladin/paladin/config/pkg/confutil"
	"github.com/LFDT-Paladin/paladin/config/pkg/pldconf"
	"github.com/LFDT-Paladin/paladin/core/mocks/componentsmocks"
	"github.com/LFDT-Paladin/paladin/core/pkg/persistence"
	"github.com/LFDT-Paladin/paladin/core/pkg/persistence/mockpersistence"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldapi"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockComponents struct {
	domainManager *componentsmocks.DomainManager
	txManager     *componentsmocks.TXManager
	allComponents *componentsmocks.AllComponents
}

func newMockComponents(t *testing.T) *mockComponents {
	m := &mockComponents{}
	m.domainManager = componentsmocks.NewDomainManager(t)
	m.txManager = componentsmocks.NewTXManager(t)
	m.allComponents = componentsmocks.NewAllComponents(t)
	m.allComponents.On("DomainManager").Return(m.domainManager)
	m.allComponents.On("TxManager").Return(m.txManager)
	return m
}

func newDBTestStateManager(t *testing.T) (context.Context, *stateManager, *mockComponents, func()) {
	ctx := context.Background()

	logConf := pldconf.LogDefaults
	logConf.Level = confutil.P("trace")
	log.InitConfig(&logConf)

	p, pDone, err := persistence.NewUnitTestPersistence(ctx, "statemgr")
	require.NoError(t, err)
	ss := NewStateManager(ctx, &pldconf.StateStoreConfig{}, p)

	m := newMockComponents(t)

	ir, err := ss.PreInit(m.allComponents)
	require.NoError(t, err)
	require.NotNil(t, ir)
	require.NotEmpty(t, ir.RPCModules)

	err = ss.PostInit(m.allComponents)
	require.NoError(t, err)

	err = ss.Start()
	require.NoError(t, err)

	return ctx, ss.(*stateManager), m, func() {
		ss.Stop()
		pDone()
	}
}

func newDBMockStateManager(t *testing.T) (context.Context, *stateManager, sqlmock.Sqlmock, *mockComponents, func()) {
	ctx := context.Background()
	p, err := mockpersistence.NewSQLMockProvider()
	require.NoError(t, err)
	ss := NewStateManager(ctx, &pldconf.StateStoreConfig{}, p.P)

	m := newMockComponents(t)

	_, err = ss.PreInit(m.allComponents)
	require.NoError(t, err)

	err = ss.PostInit(m.allComponents)
	require.NoError(t, err)

	err = ss.Start()
	require.NoError(t, err)

	return ctx, ss.(*stateManager), p.Mock, m, func() {
		ss.Stop()
		require.NoError(t, p.Mock.ExpectationsWereMet())
	}
}

func TestGetTransactionStatesUnavailable(t *testing.T) {

	ctx, ss, _, done := newDBTestStateManager(t)
	defer done()

	txID := uuid.New()
	stateID1 := pldtypes.HexBytes(pldtypes.RandBytes(32))
	stateID2 := pldtypes.HexBytes(pldtypes.RandBytes(32))
	stateID3 := pldtypes.HexBytes(pldtypes.RandBytes(32))
	stateID4 := pldtypes.HexBytes(pldtypes.RandBytes(32))

	err := ss.WriteStateFinalizations(ctx, ss.p.NOTX(),
		[]*pldapi.StateSpendRecord{
			{DomainName: "domain1", State: stateID1, Transaction: txID},
		},
		[]*pldapi.StateReadRecord{
			{DomainName: "domain1", State: stateID2, Transaction: txID},
		},
		[]*pldapi.StateConfirmRecord{
			{DomainName: "domain1", State: stateID3, Transaction: txID},
		},
		[]*pldapi.StateInfoRecord{
			{DomainName: "domain1", State: stateID4, Transaction: txID},
		})
	require.NoError(t, err)

	txStates, err := ss.GetTransactionStates(ctx, ss.p.NOTX(), txID)
	require.NoError(t, err)
	require.Empty(t, txStates.Spent)
	require.Empty(t, txStates.Read)
	require.Empty(t, txStates.Confirmed)
	require.Equal(t, []pldtypes.HexBytes{stateID1}, txStates.Unavailable.Spent)
	require.Equal(t, []pldtypes.HexBytes{stateID2}, txStates.Unavailable.Read)
	require.Equal(t, []pldtypes.HexBytes{stateID3}, txStates.Unavailable.Confirmed)
	require.Equal(t, []pldtypes.HexBytes{stateID4}, txStates.Unavailable.Info)
}

func setupWidgetsForTxStates(t *testing.T, count int) (context.Context, *stateManager, []*pldapi.State, func()) {
	ctx, ss, m, done := newDBTestStateManager(t)

	_ = mockDomain(t, m, "domain1", false)
	mockStateCallback(m)

	schema, err := newABISchema(ctx, "domain1", testABIParam(t, widgetABI))
	require.NoError(t, err)
	err = ss.persistSchemas(ctx, ss.p.NOTX(), []*pldapi.Schema{schema.Schema})
	require.NoError(t, err)

	widgetJSON := make([]string, count)
	for i := range widgetJSON {
		widgetJSON[i] = fmt.Sprintf(`{"size": %d, "color": "red", "price": 100}`, i)
	}
	widgets := makeWidgets(t, ctx, ss, "domain1", pldtypes.RandAddress(), schema.ID(), widgetJSON)
	return ctx, ss, widgets, done
}

func TestGetTransactionStatesOrdered(t *testing.T) {

	ctx, ss, widgets, done := setupWidgetsForTxStates(t, 7)
	defer done()

	missingRead := pldtypes.HexBytes(pldtypes.RandBytes(32))
	missingConfirm0 := pldtypes.HexBytes(pldtypes.RandBytes(32))
	missingConfirm2 := pldtypes.HexBytes(pldtypes.RandBytes(32))
	missingInfo := pldtypes.HexBytes(pldtypes.RandBytes(32))

	txID := uuid.New()
	err := ss.WriteStateFinalizations(ctx, ss.p.NOTX(),
		[]*pldapi.StateSpendRecord{
			{DomainName: "domain1", State: widgets[0].ID, Transaction: txID, Index: 1},
			{DomainName: "domain1", State: widgets[1].ID, Transaction: txID, Index: 0},
		},
		[]*pldapi.StateReadRecord{
			{DomainName: "domain1", State: missingRead, Transaction: txID, Index: 1},
			{DomainName: "domain1", State: widgets[2].ID, Transaction: txID, Index: 0},
		},
		[]*pldapi.StateConfirmRecord{
			{DomainName: "domain1", State: missingConfirm2, Transaction: txID, Index: 2},
			{DomainName: "domain1", State: widgets[3].ID, Transaction: txID, Index: 3},
			{DomainName: "domain1", State: missingConfirm0, Transaction: txID, Index: 0},
			{DomainName: "domain1", State: widgets[4].ID, Transaction: txID, Index: 1},
		},
		[]*pldapi.StateInfoRecord{
			{DomainName: "domain1", State: widgets[5].ID, Transaction: txID, Index: 2},
			{DomainName: "domain1", State: missingInfo, Transaction: txID, Index: 1},
			{DomainName: "domain1", State: widgets[6].ID, Transaction: txID, Index: 0},
		})
	require.NoError(t, err)

	txStates, err := ss.GetTransactionStates(ctx, ss.p.NOTX(), txID)
	require.NoError(t, err)
	ids := func(states []*pldapi.StateBase) (ids []pldtypes.HexBytes) {
		for _, s := range states {
			ids = append(ids, s.ID)
		}
		return ids
	}
	assert.Equal(t, []pldtypes.HexBytes{widgets[1].ID, widgets[0].ID}, ids(txStates.Spent))
	assert.Equal(t, []pldtypes.HexBytes{widgets[2].ID}, ids(txStates.Read))
	assert.Equal(t, []pldtypes.HexBytes{missingRead}, txStates.Unavailable.Read)
	assert.Equal(t, []pldtypes.HexBytes{widgets[4].ID, widgets[3].ID}, ids(txStates.Confirmed))
	assert.Equal(t, []pldtypes.HexBytes{missingConfirm0, missingConfirm2}, txStates.Unavailable.Confirmed)
	assert.Equal(t, []pldtypes.HexBytes{widgets[6].ID, widgets[5].ID}, ids(txStates.Info))
	assert.Equal(t, []pldtypes.HexBytes{missingInfo}, txStates.Unavailable.Info)
}

func TestGetTransactionStatesManifestUnavailable(t *testing.T) {

	ctx, ss, widgets, done := setupWidgetsForTxStates(t, 2)
	defer done()

	manifest := pldtypes.HexBytes(pldtypes.RandBytes(32))
	missingInfo := pldtypes.HexBytes(pldtypes.RandBytes(32))

	txID := uuid.New()
	err := ss.WriteStateFinalizations(ctx, ss.p.NOTX(), nil, nil, nil,
		[]*pldapi.StateInfoRecord{
			{DomainName: "domain1", State: widgets[0].ID, Transaction: txID, Index: 2},
			{DomainName: "domain1", State: missingInfo, Transaction: txID, Index: 3},
			{DomainName: "domain1", State: widgets[1].ID, Transaction: txID, Index: 1},
			{DomainName: "domain1", State: manifest, Transaction: txID, Index: 0},
		})
	require.NoError(t, err)

	txStates, err := ss.GetTransactionStates(ctx, ss.p.NOTX(), txID)
	require.NoError(t, err)
	require.Len(t, txStates.Info, 2)
	assert.Equal(t, widgets[1].ID, txStates.Info[0].ID)
	assert.Equal(t, widgets[0].ID, txStates.Info[1].ID)
	// The missing manifest is the first unavailable info state, even though later info states are available
	assert.Equal(t, []pldtypes.HexBytes{manifest, missingInfo}, txStates.Unavailable.Info)
}

func TestGetTransactionStatesUnindexedInfo(t *testing.T) {

	ctx, ss, widgets, done := setupWidgetsForTxStates(t, 1)
	defer done()

	// Records written before indexes were recorded have none, and are returned in DB order
	txID := uuid.New()
	missing := pldtypes.HexBytes(pldtypes.RandBytes(32))
	for _, stateID := range []pldtypes.HexBytes{missing, widgets[0].ID} {
		err := ss.p.DB().WithContext(ctx).Exec(`INSERT INTO state_info_records ("domain_name", "state", "transaction") VALUES (?, ?, ?)`,
			"domain1", stateID, txID).Error
		require.NoError(t, err)
	}
	txStates, err := ss.GetTransactionStates(ctx, ss.p.NOTX(), txID)
	require.NoError(t, err)
	require.Len(t, txStates.Info, 1)
	assert.Equal(t, widgets[0].ID, txStates.Info[0].ID)
	assert.Equal(t, []pldtypes.HexBytes{missing}, txStates.Unavailable.Info)
}

func TestSortRecordsByIndex(t *testing.T) {
	r := func(idx *int) *transactionStateRecord {
		return &transactionStateRecord{State: pldtypes.HexBytes(pldtypes.RandBytes(32)), Index: idx}
	}
	ordered := []*transactionStateRecord{r(confutil.P(1)), r(confutil.P(0))}
	expected := []*transactionStateRecord{ordered[1], ordered[0]}
	sortRecordsByIndex(ordered)
	assert.Equal(t, expected, ordered)

	// Any record without an index leaves the whole group in the order given
	mixed := []*transactionStateRecord{r(confutil.P(1)), r(nil), r(confutil.P(0))}
	expected = []*transactionStateRecord{mixed[0], mixed[1], mixed[2]}
	sortRecordsByIndex(mixed)
	assert.Equal(t, expected, mixed)
}

func TestGetTransactionStatesFail(t *testing.T) {

	ctx, ss, db, _, done := newDBMockStateManager(t)
	defer done()

	db.ExpectQuery("SELECT.*states").WillReturnError(fmt.Errorf("pop"))

	_, err := ss.GetTransactionStates(ctx, ss.p.NOTX(), uuid.New())
	assert.Regexp(t, "pop", err)
}
