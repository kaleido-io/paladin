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

package metrics

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestIncValidatedStateCache(t *testing.T) {
	m := InitMetrics(context.Background(), prometheus.NewRegistry())

	m.IncValidatedStateCache("hit")
	m.IncValidatedStateCache("hit")
	m.IncValidatedStateCache("miss")
	// Any non-"hit" result is counted as a miss.
	m.IncValidatedStateCache("other")

	assert.Equal(t, float64(2), testutil.ToFloat64(m.validatedStateCacheHit))
	assert.Equal(t, float64(2), testutil.ToFloat64(m.validatedStateCacheMiss))
}

func TestNoopMetrics(t *testing.T) {
	m := NewNoop()
	assert.NotNil(t, m)
	// Must not panic.
	m.IncValidatedStateCache("hit")
	m.IncValidatedStateCache("miss")
}
