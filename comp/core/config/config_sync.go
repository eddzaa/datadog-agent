// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package config

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"time"

	apiutils "github.com/DataDog/datadog-agent/pkg/api/util"
	pkgconfigmodel "github.com/DataDog/datadog-agent/pkg/config/model"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// syncConfigWithCoreAgent fetches the config from the core agent and updates the local config
func syncConfigWithCoreAgent(ctx context.Context, config pkgconfigmodel.ReaderWriter, url *url.URL, refreshInterval time.Duration) {
	ticker := time.NewTicker(refreshInterval)
	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			data, err := apiutils.DoGetWithContext(ctx, http.DefaultClient, url.String(), apiutils.LeaveConnectionOpen)
			if err != nil {
				log.Warnf("Failed to fetch config from core agent: %v", err)
				continue
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
