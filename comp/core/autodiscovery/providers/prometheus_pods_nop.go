// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !kubelet

package providers

import "github.com/DataDog/datadog-agent/pkg/config"

var NewPrometheusPodsConfigProvider func(providerConfig *config.ConfigurationProviders) (ConfigProvider, error) = nil
