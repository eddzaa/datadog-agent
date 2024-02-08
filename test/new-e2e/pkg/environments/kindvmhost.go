// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package environments

import (
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/components"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/e2e"
)

// KindVMHost is an environment that contains a Kubernetes cluster, a VM and a FakeIntake.
type KindVMHost struct {
	// Components
	KubernetesCluster *components.KubernetesCluster
	FakeIntake        *components.FakeIntake
	Agent             *components.KubernetesAgent
}

var _ e2e.Initializable = &KindVMHost{}

// Init initializes the environment
func (e *KindVMHost) Init(ctx e2e.Context) error {
	return nil
}
