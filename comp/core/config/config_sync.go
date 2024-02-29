// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package config

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"time"

	apiutils "github.com/DataDog/datadog-agent/pkg/api/util"
	pkgconfigmodel "github.com/DataDog/datadog-agent/pkg/config/model"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

func syncConfigWithCoreAgent(ctx context.Context, config pkgconfigmodel.ReaderWriter, host string, port int, refreshInterval time.Duration) {
	url := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(host, strconv.Itoa(port)),
		Path:   "/config/v1",
	}
	syncConfigWithWithURL(ctx, config, url, refreshInterval)
}

// syncConfigWithCoreAgent fetches the config from the core agent and updates the local config
func syncConfigWithWithURL(ctx context.Context, config pkgconfigmodel.ReaderWriter, url *url.URL, refreshInterval time.Duration) {
	ticker := time.NewTicker(refreshInterval)
	// whether we managed to contact the core-agent, used to avoid spamming logs
	connected := true

	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			data, err := apiutils.DoGetWithContext(ctx, http.DefaultClient, url.String(), apiutils.LeaveConnectionOpen)
			if err != nil {
				if connected {
					log.Warnf("Failed to fetch config from core agent: %v", err)
					connected = false
				}
				continue
			}

			if !connected {
				log.Debug("Succeeded to fetch config from core agent")
				connected = true
			}

			var configs map[string]interface{}
			if err := json.Unmarshal(data, &configs); err != nil {
				log.Warnf("Failed to unmarshal config from core agent: %v", err)
				continue
			}

			for k, v := range configs {
				// check if the value changed to avoid logging and triggering config change
				// notifications every time
				if reflect.DeepEqual(config.Get(k), v) {
					continue
				}
				log.Debugf("Updating config key %s from core agent", k)
				config.Set(k, v, pkgconfigmodel.SourceLocalConfigProcess)
			}
		}
	}
}
