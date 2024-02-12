// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

//go:build linux_bpf

package http2

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/network/config"
)

func TestIncompleteBuffer(t *testing.T) {
	t.Run("becoming complete", func(t *testing.T) {
		// Testing the scenario where an incomplete request becomes complete.
		buffer := NewIncompleteBuffer(config.New()).(*incompleteBuffer)
		now := time.Now()
		buffer.minAgeNano = (30 * time.Second).Nanoseconds()
		request := &ebpfTXWrapper{
			EbpfTx: &EbpfTx{
				Tuple: connTuple{
					Sport: 6000,
				},
				Stream: http2Stream{
					Response_last_seen: 0, // Required to make the request incomplete.
					Request_started:    uint64(now.UnixNano()),
					Status_code: http2InterestingValue{
						Index: uint64(K200Value),
					},
					Request_method: http2InterestingValue{
						Index: uint64(GetValue),
					},
					Path: http2InterestingValue{
						Index: uint64(EmptyPathValue),
					},
				},
			},
		}
		buffer.Add(request)
		transactions := buffer.Flush(now)
		require.Empty(t, transactions)
		assert.True(t, len(buffer.data) == 1)

		buffer.data[0].Stream.Response_last_seen = uint64(now.Add(time.Second).UnixNano())
		transactions = buffer.Flush(now)
		require.Len(t, transactions, 1)
		assert.True(t, len(buffer.data) == 0)
	})

	t.Run("removing old incomplete", func(t *testing.T) {
		// Testing the scenario where an incomplete request is removed after a certain time.
		buffer := NewIncompleteBuffer(config.New()).(*incompleteBuffer)
		now := time.Now()
		buffer.minAgeNano = (30 * time.Second).Nanoseconds()
		request := &ebpfTXWrapper{
			EbpfTx: &EbpfTx{
				Tuple: connTuple{
					Sport: 6000,
				},
				Stream: http2Stream{
					Path: http2InterestingValue{
						Index: uint64(EmptyPathValue),
					},
					Request_started: uint64(now.UnixNano()),
				},
			},
		}
		buffer.Add(request)
		_ = buffer.Flush(now)

		assert.True(t, len(buffer.data) > 0)
		now = now.Add(35 * time.Second)
		_ = buffer.Flush(now)
		assert.True(t, len(buffer.data) == 0)
	})
}
