// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

package ndmtmp

import (
	"testing"

	"github.com/DataDog/datadog-agent/comp/aggregator/demultiplexer/demultiplexerimpl"
	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/forwarder/defaultforwarder"
	"github.com/DataDog/datadog-agent/comp/forwarder/eventplatform/eventplatformimpl"
	orchestratorForwarderImpl "github.com/DataDog/datadog-agent/comp/forwarder/orchestrator/orchestratorimpl"
	ddagg "github.com/DataDog/datadog-agent/pkg/aggregator"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
	"go.uber.org/fx"
)

func TestBundleDependencies(t *testing.T) {
	fxutil.TestBundle(t, Bundle(),
		demultiplexerimpl.MockModule(),
		orchestratorForwarderImpl.MockModule(),
		defaultforwarder.MockModule(),
		eventplatformimpl.MockModule(),
		core.MockBundle(),
	)
}

func TestMockBundleDependencies(t *testing.T) {
	fxutil.TestBundle(t, MockBundle(),
		core.MockBundle(),
		fx.Provide(func() *ddagg.AgentDemultiplexer {
			return &ddagg.AgentDemultiplexer{}
		}),
	)
}
