// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newConfig() {
	config.Datadog = config.NewConfig("datadog", "DD", strings.NewReplacer(".", "_"))
	config.InitConfig(config.Datadog)
}

func TestRuntimeSecurityLoad(t *testing.T) {
	newConfig()

	for i, tc := range []struct {
		cws, fim, events bool
		enabled          bool
	}{
		{cws: false, fim: false, events: false, enabled: false},
		{cws: false, fim: false, events: true, enabled: true},
		{cws: false, fim: true, events: false, enabled: true},
		{cws: false, fim: true, events: true, enabled: true},
		{cws: true, fim: false, events: false, enabled: true},
		{cws: true, fim: false, events: true, enabled: true},
		{cws: true, fim: true, events: false, enabled: true},
		{cws: true, fim: true, events: true, enabled: true},
	} {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			os.Setenv("DD_RUNTIME_SECURITY_CONFIG_ENABLED", strconv.FormatBool(tc.cws))
			os.Setenv("DD_RUNTIME_SECURITY_CONFIG_FIM_ENABLED", strconv.FormatBool(tc.fim))
			os.Setenv("DD_RUNTIME_SECURITY_CONFIG_EVENT_MONITORING_ENABLED", strconv.FormatBool(tc.events))

			defer os.Unsetenv("DD_RUNTIME_SECURITY_CONFIG_ENABLED")
			defer os.Unsetenv("DD_RUNTIME_SECURITY_CONFIG_FIM_ENABLED")
			defer os.Unsetenv("DD_RUNTIME_SECURITY_CONFIG_EVENT_MONITORING_ENABLED")

			cfg, err := New("")
			require.NoError(t, err)
			assert.Equal(t, tc.enabled, cfg.ModuleIsEnabled(SecurityRuntimeModule))
		})
	}
}

func TestNetworkProcessEventMonitoring(t *testing.T) {
	newConfig()

	for i, te := range []struct {
		network, netProcEvents bool
		enabled                bool
	}{
		{network: false, netProcEvents: false, enabled: false},
		{network: false, netProcEvents: true, enabled: false},
		{network: true, netProcEvents: false, enabled: false},
		{network: true, netProcEvents: true, enabled: true},
	} {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			os.Setenv("DD_SYSTEM_PROBE_NETWORK_ENABLED", strconv.FormatBool(te.network))
			os.Setenv("DD_NETWORK_CONFIG_ENABLE_PROCESS_EVENT_MONITORING", strconv.FormatBool(te.netProcEvents))
			defer os.Unsetenv("DD_NETWORK_CONFIG_ENABLE_PROCESS_EVENT_MONITORING")
			defer os.Unsetenv("DD_SYSTEM_PROBE_NETWORK_ENABLED")

			cfg, err := New("")
			require.NoError(t, err)
			assert.Equal(t, te.enabled, cfg.ModuleIsEnabled(SecurityRuntimeModule))
			assert.Equal(t, te.enabled, config.Datadog.GetBool("runtime_security_config.event_monitoring.enabled"))
		})
	}

}
