// Copyright © 2026 Kaleido, Inc.
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

import { Dispatch, SetStateAction, useMemo, useState } from "react";
import {
  IFilter,
  IPaladinTransactionPagingReference,
  ITransactionPagingReference,
} from "../interfaces";

/** Paginated list view with filter support — common to all main screens. */
export interface PaginatedFilteredViewState {
  page: number;
  setPage: Dispatch<SetStateAction<number>>;
  rowsPerPage: number;
  setRowsPerPage: Dispatch<SetStateAction<number>>;
  filters: IFilter[];
  setFilters: Dispatch<SetStateAction<IFilter[]>>;
}

/** Paginated list view with filters and sort direction. */
export interface SortedPaginatedFilteredViewState
  extends PaginatedFilteredViewState {
  sortAscending: boolean;
  setSortAscending: Dispatch<SetStateAction<boolean>>;
}

/** Sorted paginated list that pages using timestamp references. */
export interface TimestampPagedViewState
  extends SortedPaginatedFilteredViewState {
  refTimestamps: string[];
  setRefTimestamps: Dispatch<SetStateAction<string[]>>;
}

export interface TransactionsViewState extends PaginatedFilteredViewState {
  refEntries: ITransactionPagingReference[];
  setRefEntries: Dispatch<SetStateAction<ITransactionPagingReference[]>>;
  showTxsWithReceipt: boolean;
  setShowTxsWithReceipt: Dispatch<SetStateAction<boolean>>;
}

export interface SubmissionsViewState
  extends SortedPaginatedFilteredViewState {
  section: "pending" | "failed";
  setSection: Dispatch<SetStateAction<"pending" | "failed">>;
  refEntries: IPaladinTransactionPagingReference[];
  setRefEntries: Dispatch<SetStateAction<IPaladinTransactionPagingReference[]>>;
}

export interface DomainsViewState extends TimestampPagedViewState {
  selectedDomain: string | undefined;
  setSelectedDomain: Dispatch<SetStateAction<string | undefined>>;
}

export type PrivacyGroupsViewState = TimestampPagedViewState;

export interface StatesViewState extends TimestampPagedViewState {
  selectedDomain: string | undefined;
  setSelectedDomain: Dispatch<SetStateAction<string | undefined>>;
  selectedSchemaId: string | undefined;
  setSelectedSchemaId: Dispatch<SetStateAction<string | undefined>>;
}

export interface MessagesViewState extends TimestampPagedViewState {
  sortBy: string;
  setSortBy: Dispatch<SetStateAction<string>>;
}

export interface RegistryViewState extends SortedPaginatedFilteredViewState {
  refNames: string[];
  setRefNames: Dispatch<SetStateAction<string[]>>;
}

export interface KeysViewState extends SortedPaginatedFilteredViewState {
  mode: "explorer" | "list";
  setMode: Dispatch<SetStateAction<"explorer" | "list">>;
  sortByPathFirst: boolean;
  setSortByPathFirst: Dispatch<SetStateAction<boolean>>;
}

export function usePaginatedFilteredViewState(
  defaultRowsPerPage = 10
): PaginatedFilteredViewState {
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(defaultRowsPerPage);
  const [filters, setFilters] = useState<IFilter[]>([]);

  return useMemo(
    () => ({ page, setPage, rowsPerPage, setRowsPerPage, filters, setFilters }),
    [page, rowsPerPage, filters]
  );
}

export function useSortedPaginatedFilteredViewState(
  defaultSortAscending = false,
  defaultRowsPerPage = 10
): SortedPaginatedFilteredViewState {
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(defaultRowsPerPage);
  const [filters, setFilters] = useState<IFilter[]>([]);
  const [sortAscending, setSortAscending] = useState(defaultSortAscending);

  return useMemo(
    () => ({
      page,
      setPage,
      rowsPerPage,
      setRowsPerPage,
      filters,
      setFilters,
      sortAscending,
      setSortAscending,
    }),
    [page, rowsPerPage, filters, sortAscending]
  );
}

export function useTimestampPagedViewState(
  defaultSortAscending = false,
  defaultRowsPerPage = 10
): TimestampPagedViewState {
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(defaultRowsPerPage);
  const [filters, setFilters] = useState<IFilter[]>([]);
  const [sortAscending, setSortAscending] = useState(defaultSortAscending);
  const [refTimestamps, setRefTimestamps] = useState<string[]>([]);

  return useMemo(
    () => ({
      page,
      setPage,
      rowsPerPage,
      setRowsPerPage,
      filters,
      setFilters,
      sortAscending,
      setSortAscending,
      refTimestamps,
      setRefTimestamps,
    }),
    [page, rowsPerPage, filters, sortAscending, refTimestamps]
  );
}
