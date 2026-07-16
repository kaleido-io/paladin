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

import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';
import { handleRpcMethod } from '../handlers/dispatch.js';
import { loadCollection, resetStore } from './dataStore.js';

afterEach(() => {
  resetStore();
});

describe('mutable store mutations', () => {
  it('create persists a listener returned by query and get', async () => {
    const baseline = loadCollection('event-listeners');
    const baselineCount = baseline.length;

    const created = await handleRpcMethod('ptx_createBlockchainEventListener', [
      {
        name: 'new-event-listener',
        started: true,
        sources: [{ abi: [], address: '0xabc' }],
        options: { batchSize: 10 },
      },
    ]);
    assert.equal(created, true);

    const listed = (await handleRpcMethod('ptx_queryBlockchainEventListeners', [
      { limit: 100 },
    ])) as Record<string, unknown>[];
    assert.equal(listed.length, baselineCount + 1);
    assert.ok(listed.some((item) => item.name === 'new-event-listener'));

    const got = (await handleRpcMethod('ptx_getBlockchainEventListener', [
      'new-event-listener',
    ])) as Record<string, unknown>;
    assert.equal(got.name, 'new-event-listener');
    assert.equal(got.started, true);
    assert.equal(typeof got.created, 'string');
  });

  it('start and stop flip the started field', async () => {
    const name = 'eventlistener01';

    const stopped = await handleRpcMethod('ptx_stopBlockchainEventListener', [name]);
    assert.equal(stopped, true);
    let got = (await handleRpcMethod('ptx_getBlockchainEventListener', [
      name,
    ])) as Record<string, unknown>;
    assert.equal(got.started, false);

    const started = await handleRpcMethod('ptx_startBlockchainEventListener', [name]);
    assert.equal(started, true);
    got = (await handleRpcMethod('ptx_getBlockchainEventListener', [
      name,
    ])) as Record<string, unknown>;
    assert.equal(got.started, true);
  });

  it('delete removes a listener from the collection', async () => {
    const name = 'eventlistener01';
    const before = loadCollection('event-listeners').length;

    const deleted = await handleRpcMethod('ptx_deleteBlockchainEventListener', [name]);
    assert.equal(deleted, true);
    assert.equal(loadCollection('event-listeners').length, before - 1);

    const got = await handleRpcMethod('ptx_getBlockchainEventListener', [name]);
    assert.equal(got, null);

    const missing = await handleRpcMethod('ptx_deleteBlockchainEventListener', [name]);
    assert.equal(missing, false);
  });

  it('resetStore restores fixture baselines after mutations', async () => {
    const baselineCount = loadCollection('event-listeners').length;

    await handleRpcMethod('ptx_createBlockchainEventListener', [
      {
        name: 'temporary-listener',
        started: false,
        sources: [],
        options: {},
      },
    ]);
    assert.equal(loadCollection('event-listeners').length, baselineCount + 1);

    resetStore();
    assert.equal(loadCollection('event-listeners').length, baselineCount);
    assert.equal(
      loadCollection('event-listeners').some((item) => item.name === 'temporary-listener'),
      false
    );
  });

  it('receipt and privacy-group listener creates persist', async () => {
    assert.equal(
      await handleRpcMethod('ptx_createReceiptListener', [
        { name: 'new-receipt-listener', started: true },
      ]),
      true
    );
    const receipt = (await handleRpcMethod('ptx_getReceiptListener', [
      'new-receipt-listener',
    ])) as Record<string, unknown>;
    assert.equal(receipt.name, 'new-receipt-listener');

    assert.equal(
      await handleRpcMethod('pgroup_createMessageListener', [
        { name: 'new-pg-listener', started: false },
      ]),
      true
    );
    const pg = (await handleRpcMethod('pgroup_getMessageListener', [
      'new-pg-listener',
    ])) as Record<string, unknown>;
    assert.equal(pg.name, 'new-pg-listener');
  });

  it('pgroup_createGroup persists and returns the full group', async () => {
    const baselineCount = loadCollection('privacy-groups').length;

    const created = (await handleRpcMethod('pgroup_createGroup', [
      {
        domain: 'pente',
        name: 'newgroup',
        members: ['alice@node1'],
      },
    ])) as Record<string, unknown>;

    assert.equal(typeof created.id, 'string');
    assert.match(created.id as string, /^0x[a-fA-F0-9]{64}$/);
    assert.equal(created.name, 'newgroup');
    assert.deepEqual(created.members, ['alice@node1']);
    assert.equal(created.domain, 'pente');
    assert.equal(loadCollection('privacy-groups').length, baselineCount + 1);

    const got = (await handleRpcMethod('pgroup_getGroupById', [
      'pente',
      created.id,
    ])) as Record<string, unknown>;
    assert.equal(got.id, created.id);
    assert.equal(got.name, 'newgroup');
  });
});
