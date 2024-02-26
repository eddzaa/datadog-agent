// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package common

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/DataDog/datadog-agent/cmd/agent/common/path"
	"github.com/DataDog/datadog-agent/comp/core/autodiscovery"
	"github.com/DataDog/datadog-agent/comp/core/secrets"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/sbom/scanner"
)

// GetWorkloadmetaInit provides the InitHelper for workloadmeta so it can be injected as a Param
// at workloadmeta comp fx injection.
func GetWorkloadmetaInit() workloadmeta.InitHelper {
	return workloadmeta.InitHelper(func(ctx context.Context, wm workloadmeta.Component) error {
		// SBOM scanner needs to be called here as initialization is required prior to the
		// catalog getting instantiated and initialized.
		sbomScanner, err := scanner.CreateGlobalScanner(config.Datadog)
		if err != nil {
			return fmt.Errorf("failed to create SBOM scanner: %s", err)
		} else if sbomScanner != nil {
			sbomScanner.Start(ctx)
		}

		return nil
	})
}

// LoadComponents configures several common Agent components:
// tagger, collector, scheduler and autodiscovery
func LoadComponents(_ secrets.Component, wmeta workloadmeta.Component, ac autodiscovery.Component, confdPath string) {
	confSearchPaths := []string{
		confdPath,
		filepath.Join(path.GetDistPath(), "conf.d"),
		"",
	}

	// setup autodiscovery. must be done after the tagger is initialized.
	if !ac.IsStarted() {
		ac.Start()
	}
	setupAutoDiscovery(confSearchPaths, wmeta, ac)
}
