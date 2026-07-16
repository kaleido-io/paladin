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

import { formatMessageId } from '../fixtures/privacy-group-data.js';
import { loadCollection, upsertItem } from '../store/dataStore.js';

/**
 * Handles pgroup_sendMessage: persists a message and returns its id string
 * (required for UI navigation to the message detail page).
 */
export const handleSendPrivacyGroupMessage = (params: unknown[]): string => {
  const raw = params[0];
  if (raw === undefined || typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new Error('pgroup_sendMessage expects a message object as params[0]');
  }

  const payload = raw as Record<string, unknown>;
  const items = loadCollection('privacy-group-messages');
  const n = items.length + 1;
  const now = new Date().toISOString();

  const item: Record<string, unknown> = {
    id: formatMessageId(n),
    localSequence: n,
    sent: now,
    received: now,
    node: 'node1',
    domain: typeof payload.domain === 'string' ? payload.domain : 'pente',
    group: payload.group,
    topic: payload.topic,
    data: payload.data,
  };

  if (typeof payload.correlationId === 'string' && payload.correlationId.length > 0) {
    item.correlationId = payload.correlationId;
  }

  upsertItem('privacy-group-messages', item, 'id');
  return item.id as string;
};
