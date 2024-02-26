// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package originresolution

import (
	"bytes"
	"strconv"
	"time"

	"github.com/DataDog/datadog-agent/pkg/util/containers/metrics/provider"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	cacheValidity = 2 * time.Second
)

var (
	// containerIDFieldPrefix is the prefix for a common field holding the sender's container ID
	containerIDFieldPrefix = []byte("c:")

	// containerInodeFieldPrefix is the prefix for a notation holding the sender's container Inode in the containerIDField
	containerIDFieldInodePrefix = []byte("in-")
)

// ResolveOrigin parses the value of the container ID field.
// The Origin Resolution works as follows, in that order:
// * If the filed is prefixed by `c:`, it corresponds to the container ID of the source
// * If the field is prefixed by `c:in-`, it corresponds to the cgroup controller's inode of the source.
func ResolveOrigin(rawContainerIDField []byte) []byte {
	p := provider.GetProvider()
	containerIDField := rawContainerIDField[len(containerIDFieldPrefix):]

	if bytes.HasPrefix(containerIDField[:len(containerIDFieldInodePrefix)], containerIDFieldInodePrefix) {
		inodeField, err := strconv.ParseUint(string(containerIDField[len(containerIDFieldPrefix)+1:]), 10, 64)
		if err != nil {
			log.Debugf("Failed to parse inode from %s, got %v", containerIDField, err)
			return nil
		}

		containerID, err := p.GetMetaCollector().GetContainerIDForInode(inodeField, cacheValidity)
		if err != nil {
			log.Debugf("Failed to get container ID, got %v", err)
			return nil
		}
		return []byte(containerID)
	}

	return containerIDField
}
