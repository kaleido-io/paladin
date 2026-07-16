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

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { FieldMap } from '../query/types.js';

const rootDir = dirname(fileURLToPath(import.meta.url));

const collectionCache = new Map<string, Record<string, unknown>[]>();
const staticCache = new Map<string, unknown>();
let fieldMaps: Record<string, FieldMap> | null = null;

const readJson = <T>(path: string): T =>
  JSON.parse(readFileSync(path, 'utf-8')) as T;

const deepClone = <T>(value: T): T => structuredClone(value);

export const getFieldMaps = (): Record<string, FieldMap> => {
  if (fieldMaps === null) {
    fieldMaps = readJson<Record<string, FieldMap>>(join(rootDir, '../fields.json'));
  }
  return fieldMaps;
};

export const getFieldMap = (collection: string): FieldMap => {
  const maps = getFieldMaps();
  return maps[collection] ?? {};
};

export const loadCollection = (collection: string): Record<string, unknown>[] => {
  const cached = collectionCache.get(collection);
  if (cached !== undefined) {
    return cached;
  }

  const filePath = join(rootDir, 'data', `${collection}.json`);
  const data = deepClone(readJson<Record<string, unknown>[]>(filePath));
  collectionCache.set(collection, data);
  return data;
};

export const loadStatic = (relativePath: string): unknown => {
  const cached = staticCache.get(relativePath);
  if (cached !== undefined) {
    return cached;
  }

  const filePath = join(rootDir, relativePath);
  const data = readJson<unknown>(filePath);
  staticCache.set(relativePath, data);
  return data;
};

/** Discard in-memory caches so the next load reloads fixtures from disk. */
export const resetStore = (): void => {
  collectionCache.clear();
  staticCache.clear();
  fieldMaps = null;
};

/** @deprecated Prefer resetStore(); kept for callers that still use the old name. */
export const clearStoreCache = resetStore;

export const upsertItem = (
  collection: string,
  item: Record<string, unknown>,
  keyField: string
): void => {
  const items = loadCollection(collection);
  const keyValue = item[keyField];
  const index = items.findIndex((existing) => existing[keyField] === keyValue);
  if (index >= 0) {
    items[index] = item;
  } else {
    items.push(item);
  }
};

export const deleteItem = (
  collection: string,
  keyField: string,
  keyValue: unknown
): boolean => {
  const items = loadCollection(collection);
  const index = items.findIndex((existing) => existing[keyField] === keyValue);
  if (index < 0) {
    return false;
  }
  items.splice(index, 1);
  return true;
};

export const updateItem = (
  collection: string,
  keyField: string,
  keyValue: unknown,
  patch: Record<string, unknown>
): boolean => {
  const items = loadCollection(collection);
  const item = items.find((existing) => existing[keyField] === keyValue);
  if (item === undefined) {
    return false;
  }
  Object.assign(item, patch);
  return true;
};
