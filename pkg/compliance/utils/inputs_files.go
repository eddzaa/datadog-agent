// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !windows

// Package utils TODO comment
package utils

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// GetFileUser exported function should have comment or be unexported
func GetFileUser(fi os.FileInfo) string {
	if statt, ok := fi.Sys().(*syscall.Stat_t); ok {
		u := strconv.Itoa(int(statt.Uid))
		if user, err := user.LookupId(u); err == nil {
			return user.Username
		}
	}
	return ""
}

// GetFileGroup exported function should have comment or be unexported
func GetFileGroup(fi os.FileInfo) string {
	if statt, ok := fi.Sys().(*syscall.Stat_t); ok {
		g := strconv.Itoa(int(statt.Gid))
		if group, err := user.LookupGroupId(g); err == nil {
			return group.Name
		}
	}
	return ""
}
