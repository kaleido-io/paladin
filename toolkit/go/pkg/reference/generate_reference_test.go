// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build reference
// +build reference

package reference

import (
	"context"
	"os"
	"testing"

	"github.com/LF-Decentralized-Trust-labs/paladin/common/go/pkg/i18n"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/language"
)

func TestGenerateMarkdownPages(t *testing.T) {
	// TODO: Generate multiple languages when supported in the future here
	ctx := i18n.WithLang(context.Background(), language.AmericanEnglish)
	markdownMap, err := GenerateObjectsReferenceMarkdown(ctx)
	require.NoError(t, err)
	assert.NotNil(t, markdownMap)

	for pageName, markdown := range markdownMap {
		f, err := os.Create(pageName)
		assert.NoError(t, err)
		_, err = f.Write(markdown)
		assert.NoError(t, err)
		err = f.Close()
		assert.NoError(t, err)
	}
}
