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

import { upsertItem } from '../store/dataStore.js';
import type { MethodConfig } from './registry.js';

export const handleCreate = (
  config: MethodConfig,
  params: unknown[]
): unknown => {
  const collection = config.collection;
  const keyField = config.keyField;
  if (collection === undefined || keyField === undefined) {
    return config.returnValue ?? false;
  }

  const paramIndex = config.paramIndex ?? 0;
  const raw = params[paramIndex];
  if (raw === undefined || typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return false;
  }

  const item: Record<string, unknown> = { ...(raw as Record<string, unknown>) };
  if (config.stampCreated === true && item.created === undefined) {
    item.created = new Date().toISOString();
  }

  upsertItem(collection, item, keyField);
  return config.returnValue ?? true;
};
