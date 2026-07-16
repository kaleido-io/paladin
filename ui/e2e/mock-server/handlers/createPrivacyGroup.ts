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

import {
  formatGenesisSalt,
  formatGenesisSchema,
  formatGenesisTxId,
  formatPrivacyGroupAddress,
  formatPrivacyGroupId,
} from '../fixtures/privacy-group-data.js';
import { loadCollection, upsertItem } from '../store/dataStore.js';

/**
 * Creates a privacy group from pgroup_createGroup params, persists it, and
 * returns the full group object (required for UI navigation by id).
 */
export const handleCreatePrivacyGroup = (params: unknown[]): Record<string, unknown> => {
  const raw = params[0];
  if (raw === undefined || typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new Error('pgroup_createGroup expects a group object as params[0]');
  }

  const payload = raw as Record<string, unknown>;
  const items = loadCollection('privacy-groups');
  const n = items.length + 1;

  const item: Record<string, unknown> = {
    id: formatPrivacyGroupId(n),
    domain: typeof payload.domain === 'string' ? payload.domain : 'pente',
    created: new Date().toISOString(),
    name: payload.name,
    members: Array.isArray(payload.members) ? payload.members : [],
    properties: {},
    configuration: {
      endorsementType: 'group',
      evmVersion: 'shanghai',
      externalCallsEnabled: true,
    },
    genesisSalt: formatGenesisSalt(n),
    genesisSchema: formatGenesisSchema(n),
    genesisTransaction: formatGenesisTxId(n),
    contractAddress: formatPrivacyGroupAddress(n),
  };

  upsertItem('privacy-groups', item, 'id');
  return item;
};
