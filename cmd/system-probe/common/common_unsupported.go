// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !linux && !windows

package common

const (
	//nolint:revive // TODO(EBPF) Fix revive linter
	DefaultLogFile = ""
)

func DisableUnsupportedKernel(isEnabled bool) bool {
	return false
}
