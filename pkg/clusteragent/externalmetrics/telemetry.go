// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build kubeapiserver
// +build kubeapiserver

package externalmetrics

import (
	"time"

	corev1 "k8s.io/api/core/v1"

	datadoghq "github.com/DataDog/datadog-operator/apis/datadoghq/v1alpha1"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/DataDog/datadog-agent/pkg/telemetry"
	le "github.com/DataDog/datadog-agent/pkg/util/kubernetes/apiserver/leaderelection/metrics"
)

const (
	ddmTelemetryValid   = "true"
	ddmTelemetryInvalid = "false"
)

var (
	ddmTelemetry = telemetry.NewGaugeWithOpts("external_metrics", "datadog_metrics",
		[]string{"namespace", "name", "valid", le.JoinLeaderLabel}, "The label valid is true if the DatadogMetric CR is valid, false otherwise",
		telemetry.Options{NoDoubleUnderscoreSep: true})

	requestsTelemetry = telemetry.NewGaugeWithOpts("external_metrics", "api_requests",
		[]string{"namespace", "handler", "in_error"}, "Count of API Requests received",
		telemetry.Options{NoDoubleUnderscoreSep: true})

	elapsedTelemetry = telemetry.NewHistogramWithOpts("external_metrics", "api_elapsed",
		[]string{"namespace", "handler", "in_error"}, "Count of API Requests received",
		prometheus.DefBuckets,
		telemetry.Options{NoDoubleUnderscoreSep: true})
)

func setDatadogMetricTelemetry(ddm *datadoghq.DatadogMetric) {
	unsetDatadogMetricTelemetry(ddm.Namespace, ddm.Name)

	var validValue string
	switch isDatadogMetricValid(ddm) {
	case true:
		validValue = ddmTelemetryValid
	case false:
		validValue = ddmTelemetryInvalid
	}

	ddmTelemetry.Set(1.0, ddm.Namespace, ddm.Name, validValue, le.JoinLeaderValue)
}

func unsetDatadogMetricTelemetry(ns, name string) {
	ddmTelemetry.Delete(ns, name, ddmTelemetryValid, le.JoinLeaderValue)
	ddmTelemetry.Delete(ns, name, ddmTelemetryInvalid, le.JoinLeaderValue)
}

func isDatadogMetricValid(ddm *datadoghq.DatadogMetric) bool {
	for _, condition := range ddm.Status.Conditions {
		if condition.Type == datadoghq.DatadogMetricConditionTypeValid {
			return condition.Status == corev1.ConditionTrue
		}
	}

	return false
}

func setQueryTelemtry(handler, namespace string, startTime time.Time, err error) {
	// Handle telemtry
	inErrror := "false"
	if err != nil {
		inErrror = "true"
	}

	requestsTelemetry.Inc(namespace, handler, inErrror)
	elapsedTelemetry.Observe(float64(time.Since(startTime)), namespace, handler, inErrror)
}
