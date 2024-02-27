// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package config

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/config/model"
)

func TestSyncConfigWithCoreAgent(t *testing.T) {
	configCore := model.NewConfig("test", "DD", strings.NewReplacer(".", "_"))
	configCore.Set("api_key", "api_key_core1", model.SourceFile)

	configRemote := model.NewConfig("test", "DD", strings.NewReplacer(".", "_"))
	configRemote.Set("api_key", "api_key_remote", model.SourceEnvVar)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := configCore.GetString("api_key")
		w.Write([]byte(fmt.Sprintf(`{"api_key": "%s"}`, key)))
	})

	server := httptest.NewServer(handler)
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	refreshInterval := time.Millisecond * 100
	sleepInterval := 2 * refreshInterval

	url := &url.URL{
		Scheme: "http",
		Host:   server.Listener.Addr().String(),
	}
	go syncConfigWithCoreAgent(ctx, configRemote, url, refreshInterval)

	time.Sleep(sleepInterval)
	require.Equal(t, "api_key_core1", configRemote.GetString("api_key"))
	require.Equal(t, model.SourceLocalConfigProcess, configRemote.GetSource("api_key"))

	configCore.Set("api_key", "api_key_core2", model.SourceAgentRuntime)

	time.Sleep(sleepInterval)
	require.Equal(t, "api_key_core2", configRemote.GetString("api_key"))
	require.Equal(t, model.SourceLocalConfigProcess, configRemote.GetSource("api_key"))
}
