// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

package main

import (
	"context"
	"github.com/DataDog/datadog-agent/cmd/agentless-scanner/azureutils"
	"github.com/DataDog/datadog-agent/cmd/agentless-scanner/runner"
	"github.com/DataDog/datadog-agent/cmd/agentless-scanner/types"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/spf13/cobra"
	"time"
)

func azureGroupCommand(parent *cobra.Command) *cobra.Command {
	cmd := &cobra.Command{
		Use:               "azure",
		Short:             "Datadog Agentless Scanner at your service.",
		Long:              `Datadog Agentless Scanner scans your cloud environment for vulnerabilities, compliance and security issues.`,
		SilenceUsage:      true,
		PersistentPreRunE: parent.PersistentPreRunE,
	}
	cmd.AddCommand(azureAttachCommand())
	//cmd.AddCommand(azureCleanupCommand())
	//cmd.AddCommand(azureOfflineCommand())
	//cmd.AddCommand(azureScanCommand())
	//cmd.AddCommand(azureSnapshotCommand())
	return cmd
}

func azureAttachCommand() *cobra.Command {
	var flags struct {
		noMount bool
	}
	cmd := &cobra.Command{
		Use:   "attach <snapshot|volume>",
		Short: "Attaches a snapshot or volume to the current instance",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := ctxTerminated()
			self, err := azureutils.GetInstanceMetadata(context.Background())
			if err != nil {
				return err
			}
			resourceID, err := types.HumanParseCloudID(args[0], types.CloudProviderAzure, self.Compute.Location, self.Compute.SubscriptionID)
			if err != nil {
				return err
			}
			return azureAttachCmd(ctx, resourceID, !flags.noMount, globalFlags.diskMode, globalFlags.defaultActions)
		},
	}
	cmd.Flags().BoolVar(&flags.noMount, "no-mount", false, "mount the device")
	return cmd
}

func azureAttachCmd(ctx context.Context, resourceID types.CloudID, mount bool, diskMode types.DiskMode, defaultActions []types.ScanAction) error {
	scannerHostname := tryGetHostname(ctx)
	scannerID := types.ScannerID{Hostname: scannerHostname, Provider: types.CloudProviderAzure}

	roles := getDefaultRolesMapping(types.CloudProviderAzure)
	cfg, err := azureutils.GetConfigFromCloudID(ctx, resourceID)
	scan, err := types.NewScanTask(
		types.TaskTypeEBS,
		"azure:"+resourceID.AsText(),
		scannerID,
		resourceID.ResourceName(),
		nil,
		defaultActions,
		roles,
		diskMode)
	if err != nil {
		return err
	}

	defer func() {
		ctxCleanup, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		runner.CleanupScanDir(ctxCleanup, scan)
		var waiter azureutils.ResourceWaiter
		for resourceID := range scan.CreatedResources {
			log.Debugf("Cleaning up resource %q\n", resourceID)
			if err := azureutils.CleanupScan(ctxCleanup, cfg, scan, &waiter, resourceID); err != nil {
				log.Errorf("%s: could not cleanup resource %q: %v", scan, resourceID, err)
			}
		}
	}()

	log.Infof("Setting up disk %s\n", scan.TargetID)

	var waiter azureutils.ResourceWaiter
	if err := azureutils.SetupDisk(ctx, cfg, scan, &waiter); err != nil {
		return err
	}

	log.Infof("Set up disk on NBD device %v\n", *scan.AttachedDeviceName)

	<-ctx.Done()

	return nil
}
