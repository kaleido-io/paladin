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

	"github.com/prometheus/client_golang/prometheus"
)

var METRICS_SUBSYSTEM = "state_manager"

type StateManagerMetrics interface {
	IncValidatedStateCache(result string) // result = "hit" | "miss"
}

type stateManagerMetrics struct {
	validatedStateCacheHit  prometheus.Counter
	validatedStateCacheMiss prometheus.Counter
}

func InitMetrics(ctx context.Context, registry *prometheus.Registry) *stateManagerMetrics {
	validatedStateCache := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "validated_state_cache_total", Help: "Validated-state cache lookups by result",
		Subsystem: METRICS_SUBSYSTEM}, []string{"result"})
	registry.MustRegister(validatedStateCache)
	// Pre-resolve the per-result counters so hot-path Inc calls avoid allocating a label map.
	return &stateManagerMetrics{
		validatedStateCacheHit:  validatedStateCache.WithLabelValues("hit"),
		validatedStateCacheMiss: validatedStateCache.WithLabelValues("miss"),
	}
}

func (m *stateManagerMetrics) IncValidatedStateCache(result string) {
	if result == "hit" {
		m.validatedStateCacheHit.Inc()
		return
	}
	m.validatedStateCacheMiss.Inc()
}

// noopMetrics is used when no registry is wired (e.g. unit tests that do not assert on metrics).
type noopMetrics struct{}

func NewNoop() StateManagerMetrics { return &noopMetrics{} }

func (*noopMetrics) IncValidatedStateCache(string) {}
