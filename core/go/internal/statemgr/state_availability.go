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
	"context"
	"fmt"

	"github.com/LFDT-Paladin/paladin/core/pkg/persistence"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldapi"
	"github.com/LFDT-Paladin/paladin/sdk/go/pkg/pldtypes"
)

// The spent/confirmed columns are denormalized from state_spend_records/state_confirm_records so the
// "available" query can use the states_available partial index instead of anti-joining the
// ever-growing record tables. The UPDATEs that maintain them are scoped to one domain (state IDs are
// unique only within a domain — the states PK is (domain_name, id)) and use single-column "id IN ?"
// because the persistence layer rewrites IN lists to postgres "= ANY(array)", which cannot express a
// composite key. The "<column> = FALSE" guard makes re-setting an already-TRUE flag a no-op, so
// duplicate finalizations don't churn the row version and the states_available index.
const (
	availabilityFlagConfirmed = "confirmed"
	availabilityFlagSpent     = "spent"
)

// availabilityFlagLock serializes the two paths that maintain the spent/confirmed flags: the
// finalization setters (setStatesConfirmed/setStatesSpent in WriteStateFinalizations) and the
// arrival-path reconcile (reconcileAvailabilityFlags). A record can be written before its state row
// exists, so whichever transaction commits second must observe the other's committed rows/records for
// each flag to be set exactly once regardless of arrival order. On SQLite and in tests it is a no-op.
const availabilityFlagLock = "state_availability_flags"

func setStatesConfirmed(ctx context.Context, dbTX persistence.DBTX, confirms []*pldapi.StateConfirmRecord) error {
	idsByDomain := make(map[string][]pldtypes.HexBytes, 1)
	for _, c := range confirms {
		idsByDomain[c.DomainName] = append(idsByDomain[c.DomainName], c.State)
	}
	for domainName, ids := range idsByDomain {
		if err := dbTX.DB(ctx).
			Table("states").
			Where("domain_name = ?", domainName).
			Where("id IN ?", ids).
			Where(`"confirmed" = FALSE`).
			Update(availabilityFlagConfirmed, true).
			Error; err != nil {
			return err
		}
	}
	return nil
}

func setStatesSpent(ctx context.Context, dbTX persistence.DBTX, spends []*pldapi.StateSpendRecord) error {
	idsByDomain := make(map[string][]pldtypes.HexBytes, 1)
	for _, s := range spends {
		idsByDomain[s.DomainName] = append(idsByDomain[s.DomainName], s.State)
	}
	for domainName, ids := range idsByDomain {
		if err := dbTX.DB(ctx).
			Table("states").
			Where("domain_name = ?", domainName).
			Where("id IN ?", ids).
			Where(`"spent" = FALSE`).
			Update(availabilityFlagSpent, true).
			Error; err != nil {
			return err
		}
	}
	return nil
}

// reconcileAvailabilityFlags sets the confirmed/spent flags for any just-arrived state whose record
// was written before the state row existed. Each flag is set from the authoritative record table via
// EXISTS. It takes availabilityFlagLock to serialize against the finalization path which writes the
// state records.
func (ss *stateManager) reconcileAvailabilityFlags(ctx context.Context, dbTX persistence.DBTX, states []*pldapi.State) error {
	if len(states) == 0 {
		return nil
	}
	if err := ss.p.TakeNamedLock(ctx, dbTX, availabilityFlagLock); err != nil {
		return err
	}

	idsByDomain := make(map[string][]pldtypes.HexBytes, 1)
	for _, s := range states {
		idsByDomain[s.DomainName] = append(idsByDomain[s.DomainName], s.ID)
	}

	for domainName, ids := range idsByDomain {
		if err := reconcileAvailabilityFlag(ctx, dbTX, domainName, ids, availabilityFlagConfirmed, "state_confirm_records"); err != nil {
			return err
		}
		if err := reconcileAvailabilityFlag(ctx, dbTX, domainName, ids, availabilityFlagSpent, "state_spend_records"); err != nil {
			return err
		}
	}
	return nil
}

// reconcileAvailabilityFlag sets one flag column TRUE for the given domain's states that have a
// matching row in the authoritative record table.
func reconcileAvailabilityFlag(ctx context.Context, dbTX persistence.DBTX, domainName string, ids []pldtypes.HexBytes, column, recordTable string) error {
	return dbTX.DB(ctx).
		Table("states").
		Where("domain_name = ?", domainName).
		Where("id IN ?", ids).
		Where(fmt.Sprintf(`"%s" = FALSE`, column)).
		Where(fmt.Sprintf(`EXISTS (SELECT 1 FROM %s r WHERE r.domain_name = states.domain_name AND r.state = states.id)`, recordTable)).
		Update(column, true).
		Error
}
