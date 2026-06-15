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

import { useQuery } from "@tanstack/react-query";
import {
  createContext,
  Dispatch,
  SetStateAction,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { ErrorDialog } from "../dialogs/Error";
import { fetchLatestBlockWithTxs } from "../queries/blocks";
import { constants } from "../components/config";
import {
  IPaladinTransactionPagingReference,
  ITransactionPagingReference,
} from "../interfaces";
import {
  DomainsViewState,
  KeysViewState,
  MessagesViewState,
  PrivacyGroupsViewState,
  RegistryViewState,
  StatesViewState,
  SubmissionsViewState,
  TransactionsViewState,
  usePaginatedFilteredViewState,
  useSortedPaginatedFilteredViewState,
  useTimestampPagedViewState,
} from "./viewState";

export type {
  DomainsViewState,
  KeysViewState,
  MessagesViewState,
  PaginatedFilteredViewState,
  PrivacyGroupsViewState,
  RegistryViewState,
  SortedPaginatedFilteredViewState,
  StatesViewState,
  SubmissionsViewState,
  TimestampPagedViewState,
  TransactionsViewState,
} from "./viewState";

interface IApplicationContext {
  colorMode: {
    toggleColorMode: () => void;
  };
  lastBlockWithTransactions: number;
  autoRefreshEnabled: boolean;
  setAutoRefreshEnabled: Dispatch<SetStateAction<boolean>>;
  refreshRequired: boolean;
  refresh: () => void;
  navigationVisible: boolean;
  setNavigationVisible: Dispatch<SetStateAction<boolean>>;
  transactions: TransactionsViewState;
  submissions: SubmissionsViewState;
  domains: DomainsViewState;
  privacyGroups: PrivacyGroupsViewState;
  states: StatesViewState;
  messages: MessagesViewState;
  registry: RegistryViewState;
  keys: KeysViewState;
}

export const ApplicationContext = createContext({} as IApplicationContext);

export const useApplicationContext = () => useContext(ApplicationContext);

interface Props {
  colorMode: {
    toggleColorMode: () => void;
  };
  children: JSX.Element;
}

export const ApplicationContextProvider = ({ children, colorMode }: Props) => {
  const [autoRefreshEnabled, setAutoRefreshEnabled] = useState(false);
  const [lastBlockWithTransactions, setLastBlockWithTransactions] =
    useState(-1);
  const [refreshRequired, setRefreshRequired] = useState(false);
  const [navigationVisible, setNavigationVisible] = useState(false);

  const paginated = usePaginatedFilteredViewState();
  const [txRefEntries, setTxRefEntries] = useState<
    ITransactionPagingReference[]
  >([]);
  const [txShowTxsWithReceipt, setTxShowTxsWithReceipt] = useState(true);
  const transactions = useMemo(
    (): TransactionsViewState => ({
      ...paginated,
      refEntries: txRefEntries,
      setRefEntries: setTxRefEntries,
      showTxsWithReceipt: txShowTxsWithReceipt,
      setShowTxsWithReceipt: setTxShowTxsWithReceipt,
    }),
    [paginated, txRefEntries, txShowTxsWithReceipt]
  );

  const sortedPaginated = useSortedPaginatedFilteredViewState(false);
  const [submissionsSection, setSubmissionsSection] = useState<
    "pending" | "failed"
  >("pending");
  const [submissionsRefEntries, setSubmissionsRefEntries] = useState<
    IPaladinTransactionPagingReference[]
  >([]);
  const submissions = useMemo(
    (): SubmissionsViewState => ({
      ...sortedPaginated,
      section: submissionsSection,
      setSection: setSubmissionsSection,
      refEntries: submissionsRefEntries,
      setRefEntries: setSubmissionsRefEntries,
    }),
    [sortedPaginated, submissionsSection, submissionsRefEntries]
  );

  const timestampPaged = useTimestampPagedViewState(false);
  const [domainsSelectedDomain, setDomainsSelectedDomain] = useState<
    string | undefined
  >();
  const domains = useMemo(
    (): DomainsViewState => ({
      ...timestampPaged,
      selectedDomain: domainsSelectedDomain,
      setSelectedDomain: setDomainsSelectedDomain,
    }),
    [timestampPaged, domainsSelectedDomain]
  );

  const privacyGroups = useTimestampPagedViewState(false);

  const statesPaged = useTimestampPagedViewState(false);
  const [statesSelectedDomain, setStatesSelectedDomain] = useState<
    string | undefined
  >();
  const [statesSelectedSchemaId, setStatesSelectedSchemaId] = useState<
    string | undefined
  >();
  const states = useMemo(
    (): StatesViewState => ({
      ...statesPaged,
      selectedDomain: statesSelectedDomain,
      setSelectedDomain: setStatesSelectedDomain,
      selectedSchemaId: statesSelectedSchemaId,
      setSelectedSchemaId: setStatesSelectedSchemaId,
    }),
    [statesPaged, statesSelectedDomain, statesSelectedSchemaId]
  );

  const messagesPaged = useTimestampPagedViewState(false);
  const [messagesSortBy, setMessagesSortBy] = useState("created");
  const messages = useMemo(
    (): MessagesViewState => ({
      ...messagesPaged,
      sortBy: messagesSortBy,
      setSortBy: setMessagesSortBy,
    }),
    [messagesPaged, messagesSortBy]
  );

  const registrySorted = useSortedPaginatedFilteredViewState(true);
  const [registryRefNames, setRegistryRefNames] = useState<string[]>([]);
  const registry = useMemo(
    (): RegistryViewState => ({
      ...registrySorted,
      refNames: registryRefNames,
      setRefNames: setRegistryRefNames,
    }),
    [registrySorted, registryRefNames]
  );

  const keysSorted = useSortedPaginatedFilteredViewState(true);
  const [keysMode, setKeysMode] = useState<"explorer" | "list">("list");
  const [keysSortByPathFirst, setKeysSortByPathFirst] = useState(true);
  const keys = useMemo(
    (): KeysViewState => ({
      ...keysSorted,
      mode: keysMode,
      setMode: setKeysMode,
      sortByPathFirst: keysSortByPathFirst,
      setSortByPathFirst: setKeysSortByPathFirst,
    }),
    [keysSorted, keysMode, keysSortByPathFirst]
  );

  const { data: actualLastBlockWithTransactions, error } = useQuery({
    queryKey: ["lastBlockWithTransactions"],
    queryFn: () =>
      fetchLatestBlockWithTxs().then((res) => {
        if (res.length > 0) {
          return res[0].blockNumber;
        }
        return 0;
      }),
    refetchInterval: constants.UPDATE_FREQUENCY_MILLISECONDS,
    retry: false,
    enabled: false, // TODO: remove
  });

  useEffect(() => {
    if (
      actualLastBlockWithTransactions !== undefined &&
      actualLastBlockWithTransactions > lastBlockWithTransactions
    ) {
      if (autoRefreshEnabled || lastBlockWithTransactions === -1) {
        setLastBlockWithTransactions(actualLastBlockWithTransactions);
      } else {
        setRefreshRequired(true);
      }
    }
  }, [
    actualLastBlockWithTransactions,
    lastBlockWithTransactions,
    autoRefreshEnabled,
  ]);

  const refresh = () => {
    if (actualLastBlockWithTransactions !== undefined) {
      setLastBlockWithTransactions(actualLastBlockWithTransactions);
    }
    setRefreshRequired(false);
  };

  return (
    <ApplicationContext.Provider
      value={{
        lastBlockWithTransactions,
        colorMode,
        autoRefreshEnabled,
        setAutoRefreshEnabled,
        refreshRequired,
        refresh,
        navigationVisible,
        setNavigationVisible,
        transactions,
        submissions,
        domains,
        privacyGroups,
        states,
        messages,
        registry,
        keys,
      }}
    >
      {children}
      <ErrorDialog dialogOpen={!!error} message={error?.message ?? ""} />
    </ApplicationContext.Provider>
  );
};
