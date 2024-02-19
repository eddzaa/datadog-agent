// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package telemetry defines the telemetry for the Workloadmeta component.
package telemetry

import "github.com/DataDog/datadog-agent/pkg/telemetry"

const subsystem = "workloadmeta"

var (
	// StatusSuccess is the value for the "status" tag that represents a successful operation
	StatusSuccess = "success"
	// StatusError is the value for the "status" tag that represents an error
	StatusError = "error"

	commonOpts = telemetry.Options{NoDoubleUnderscoreSep: true}
)

var (
	// StoredEntities tracks how many entities are stored in the workloadmeta store.
	StoredEntities = telemetry.NewGaugeWithOpts(
		subsystem,
		"stored_entities",
		[]string{"kind", "source"},
		"Number of entities in the store.",
		commonOpts,
	)

	// Subscribers tracks the number of subscribers.
	Subscribers = telemetry.NewGaugeWithOpts(
		subsystem,
		"subscribers",
		[]string{},
		"Number of subscribers.",
		commonOpts,
	)

	// EventsReceived tracks the number of events received.
	EventsReceived = telemetry.NewCounterWithOpts(
		subsystem,
		"events_received",
		[]string{"kind", "source"},
		"Number of events received by the workloadmeta store.",
		commonOpts,
	)

	// PullErrors tracks the number of errors that the workloadmeta received
	// when pulling from the collectors.
	PullErrors = telemetry.NewCounterWithOpts(
		subsystem,
		"pull_errors",
		[]string{"collector_id"},
		"Pulls by the workloadmeta to the collectors that returned an error",
		commonOpts,
	)

	// PullDuration measures the time that it takes to pull from the
	// workloadmeta collectors.
	PullDuration = telemetry.NewHistogramWithOpts(
		subsystem,
		"pull_duration",
		[]string{"collector_id"},
		"The time it takes to pull from the collectors (in seconds)",
		[]float64{0.25, 0.5, 0.75, 1, 2, 5, 10, 15, 30, 45, 60},
		commonOpts,
	)

	// HandleEventsDuration measures the time that it takes to handle events from the
	// workloadmeta collectors.
	HandleEventsDuration = telemetry.NewHistogramWithOpts(
		subsystem,
		"handle_events_duration",
		[]string{},
		"The time it takes to handle events from the collectors (in seconds)",
		[]float64{0.25, 0.5, 0.75, 1, 2, 5, 10, 15, 30, 45, 60},
		commonOpts,
	)

	// NotifyDuration measures the time that it takes to notify events to the
	// workloadmeta event channel.
	NotifyDuration = telemetry.NewHistogramWithOpts(
		subsystem,
		"notify_duration",
		[]string{},
		"The time it takes to notify events to the workloadmeta collector event channel (in seconds)",
		[]float64{0.1, 0.25, 0.5, 1, 3, 5, 10},
		commonOpts,
	)

	// NotificationsSent tracks the number of notifications sent from the
	// workloadmeta store to its subscribers. Note that each notification can
	// include multiple events.
	NotificationsSent = telemetry.NewCounterWithOpts(
		subsystem,
		"notifications_sent",
		[]string{"subscriber_name", "status"},
		"Number of notifications sent by workloadmeta to its subscribers",
		commonOpts,
	)

	// RemoteClientErrors tracks the number of errors on the remote workloadmeta
	// client while receiving events.
	RemoteClientErrors = telemetry.NewCounterWithOpts(
		subsystem,
		"remote_client_errors",
		[]string{"collector"},
		"Number of errors on the remote workloadmeta client while receiving events",
		commonOpts,
	)

	// RemoteServerErrors track the number of errors on the remote workloadmeta
	// server while streaming events.
	RemoteServerErrors = telemetry.NewCounterWithOpts(
		subsystem,
		"remote_server_errors",
		[]string{},
		"Number of errors on the remote workloadmeta server while streaming events",
		commonOpts,
	)
)
