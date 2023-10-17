// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package containers

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/runner"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/runner/parameters"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/utils/infra"
	"github.com/DataDog/test-infra-definitions/scenarios/aws/ecs"

	"github.com/cenkalti/backoff"
	"github.com/fatih/color"
	"github.com/pulumi/pulumi/sdk/v3/go/auto"
	"github.com/stretchr/testify/require"
	datadog "gopkg.in/zorkian/go-datadog-api.v2"
)

func TestECSSuite(t *testing.T) {
	ctx := context.Background()

	// Creating the stack
	stackConfig := runner.ConfigMap{
		"ddinfra:aws/ecs/linuxECSOptimizedNodeGroup": auto.ConfigValue{Value: "true"},
		"ddinfra:aws/ecs/linuxBottlerocketNodeGroup": auto.ConfigValue{Value: "true"},
		"ddinfra:aws/ecs/windowsLTSCNodeGroup":       auto.ConfigValue{Value: "true"},
		"ddagent:deploy":                             auto.ConfigValue{Value: "true"},
		"ddagent:fakeintake":                         auto.ConfigValue{Value: "true"},
		"ddtestworkload:deploy":                      auto.ConfigValue{Value: "true"},
	}

	_, stackOutput, err := infra.GetStackManager().GetStack(context.Background(), "ecs-cluster", stackConfig, ecs.Run, false)
	require.NoError(t, err)

	t.Cleanup(func() {
		infra.GetStackManager().DeleteStack(ctx, "ecs-cluster")
	})

	ecsClusterName := stackOutput.Outputs["ecs-cluster-name"].Value.(string)
	ecsTaskFamily := stackOutput.Outputs["agent-fargate-task-family"].Value.(string)
	ecsTaskVersion := stackOutput.Outputs["agent-fargate-task-version"].Value.(float64)

	startTime := time.Now()

	// Check content in Datadog
	apiKey, err := runner.GetProfile().SecretStore().Get(parameters.APIKey)
	require.NoError(t, err)
	appKey, err := runner.GetProfile().SecretStore().Get(parameters.APPKey)
	require.NoError(t, err)
	datadogClient := datadog.NewClient(apiKey, appKey)
	query := fmt.Sprintf("avg:ecs.fargate.cpu.user{ecs_cluster_name:%s,ecs_task_family:%s,ecs_task_version:%.0f} by {ecs_container_name}", ecsClusterName, ecsTaskFamily, ecsTaskVersion)
	t.Log(query)

	err = backoff.Retry(func() error {
		currentTime := time.Now().Unix()
		series, err := datadogClient.QueryMetrics(currentTime-120, currentTime, query)
		if err != nil {
			return err
		}

		if len(series) == 0 {
			return errors.New("No data yet")
		}

		if len(series) != 3 {
			return errors.New("Not all containers")
		}

		if series[0].Points[0][1] == nil || *series[0].Points[0][1] == 0 {
			return errors.New("0-value")
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(20*time.Second), 20))
	require.NoError(t, err)

	endTime := time.Now()

	color.NoColor = false
	c := color.New(color.Bold).SprintfFunc()
	t.Log(c("The data produced and asserted by these tests can be viewed on this dashboard:"))
	c = color.New(color.Bold, color.FgBlue).SprintfFunc()
	t.Log(c("https://dddev.datadoghq.com/dashboard/mnw-tdr-jd8/e2e-tests-containers-ecs?refresh_mode=paused&tpl_var_ecs_cluster_name%%5B0%%5D=%s&from_ts=%d&to_ts=%d&live=false",
		stackOutput.Outputs["ecs-cluster-name"].Value.(string),
		startTime.UnixMilli(),
		endTime.UnixMilli(),
	))
}
