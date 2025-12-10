/*
 * Copyright © 2025 Kaleido, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package keymanagersigningmodule

const (
	ECDSA_256     string = "ecdsa_256"
	DIGEST_TO_RSV string = "digest:rsv"
	ADDRESS_ETH   string = "address_ethereum"
	EC_NIST_P256  string = "secp256k1"
)

type ResolveKeyRequest struct {
	KeyIdentifier                  *KeyIdentifier `json:"identifier"`
	PublicIdentifierTypesToResolve []string       `json:"publicIdentifierTypesToResolve,omitempty"`
	KeySpec                        string         `json:"spec,omitempty"`
	AutoKeyCreation                bool           `json:"autoKeyCreation"`
	AutoPublicIdentifiersCreation  bool           `json:"autoPublicIdentifierCreation"`
}

type ResolveKeyResponse struct {
	ID          string              `json:"id,omitempty"`
	Identifiers []*PublicIdentifier `json:"publicIdentifiers,omitempty"`
}

type SignRequest struct {
	KeyIdentifier    *KeyIdentifier `json:"identifier,omitempty"`
	SigningFormat    string         `json:"format"`
	SigningAlgorithm string         `json:"algorithm"`
	Payload          string         `json:"payload"`
}

type SignResponse struct {
	Payload string `json:"payload"`
}

type KeyIdentifier struct {
	KeyID  *string `json:"id,omitempty"`
	KeyURI *string `json:"uri,omitempty"`
}

type PublicIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}
