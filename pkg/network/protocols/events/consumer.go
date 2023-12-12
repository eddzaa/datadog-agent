// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package events

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"go.uber.org/atomic"

	ddebpf "github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/telemetry"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	manager "github.com/DataDog/ebpf-manager"
)

const (
	batchMapSuffix  = "_batches"
	eventsMapSuffix = "_batch_events"
	sizeOfBatch     = int(unsafe.Sizeof(batch{}))
)

var errInvalidPerfEvent = errors.New("invalid perf event")

// Consumer provides a standardized abstraction for consuming (batched) events from eBPF
type Consumer[V any] struct {
	mux         sync.Mutex
	proto       string
	syncRequest chan (chan struct{})
	offsets     *offsetManager
	handler     *ddebpf.PerfHandler
	batchReader *batchReader
	callback    func([]V)

	// termination
	eventLoopWG sync.WaitGroup
	stopped     bool

	// telemetry
	metricGroup        *telemetry.MetricGroup
	eventsCount        *telemetry.Counter
	missesCount        *telemetry.Counter
	kernelDropsCount   *telemetry.Counter
	invalidEventsCount *telemetry.Counter
	batchSize          *atomic.Int64
}

// NewConsumer instantiates a new event Consumer
// `callback` is executed once for every "event" generated on eBPF and must:
// 1) copy the data it wishes to hold since the underlying byte array is reclaimed;
// 2) be thread-safe, as the callback may be executed concurrently from multiple go-routines;
func NewConsumer[V any](proto string, ebpf *manager.Manager, callback func([]V)) (*Consumer[V], error) {
	batchMapName := proto + batchMapSuffix
	batchMap, found, _ := ebpf.GetMap(batchMapName)
	if !found {
		return nil, fmt.Errorf("unable to find map %s", batchMapName)
	}

	eventsMapName := proto + eventsMapSuffix
	eventsMap, found, _ := ebpf.GetMap(eventsMapName)
	if !found {
		return nil, fmt.Errorf("unable to find map %s", eventsMapName)
	}

	numCPUs := int(eventsMap.MaxEntries())
	offsets := newOffsetManager(numCPUs)
	batchReader, err := newBatchReader(offsets, batchMap, numCPUs)
	if err != nil {
		return nil, err
	}

	handler := getHandler(proto)
	if handler == nil {
		return nil, fmt.Errorf("unable to detect perf handler. perhaps you forgot to call events.Configure()?")
	}

	// setup telemetry
	metricGroup := telemetry.NewMetricGroup(
		fmt.Sprintf("usm.%s", proto),
		telemetry.OptStatsd,
	)

	eventsCount := metricGroup.NewCounter("events_captured")
	missesCount := metricGroup.NewCounter("events_missed")
	kernelDropsCount := metricGroup.NewCounter("kernel_dropped_events")
	invalidEventsCount := metricGroup.NewCounter("invalid_events")

	return &Consumer[V]{
		proto:       proto,
		callback:    callback,
		syncRequest: make(chan chan struct{}),
		offsets:     offsets,
		handler:     handler,
		batchReader: batchReader,

		// telemetry
		metricGroup:        metricGroup,
		eventsCount:        eventsCount,
		missesCount:        missesCount,
		kernelDropsCount:   kernelDropsCount,
		invalidEventsCount: invalidEventsCount,

		batchSize: atomic.NewInt64(0),
	}, nil
}

// Start consumption of eBPF events
func (c *Consumer[V]) Start() {
	c.eventLoopWG.Add(1)
	go func() {
		defer c.eventLoopWG.Done()
		for {
			select {
			case dataEvent, ok := <-c.handler.DataChannel:
				if !ok {
					return
				}

				b, err := batchFromEventData(dataEvent.Data)
				if err == nil {
					c.process(dataEvent.CPU, b, false)
				} else {
					c.invalidEventsCount.Add(1)
				}
				dataEvent.Done()
			case _, ok := <-c.handler.LostChannel:
				if !ok {
					return
				}

				missedEvents := c.batchSize.Load()
				c.missesCount.Add(missedEvents)
			case done, ok := <-c.syncRequest:
				if !ok {
					return
				}

				c.batchReader.ReadAll(func(cpu int, b *batch) {
					c.process(cpu, b, true)
				})
				log.Infof("usm events summary: name=%q %s", c.proto, c.metricGroup.Summary())
				close(done)
			}
		}
	}()
}

// Sync userpace with kernelspace by fetching all buffered data on eBPF
// Calling this will block until all eBPF map data has been fetched and processed
func (c *Consumer[V]) Sync() {
	c.mux.Lock()
	if c.stopped {
		c.mux.Unlock()
		return
	}

	request := make(chan struct{})
	c.syncRequest <- request
	c.mux.Unlock()

	// Wait until all data is fetch from eBPF
	<-request
}

// Stop consuming data from eBPF
func (c *Consumer[V]) Stop() {
	c.mux.Lock()
	defer c.mux.Unlock()

	if c.stopped {
		return
	}

	c.stopped = true
	c.batchReader.Stop()
	c.handler.Stop()
	c.eventLoopWG.Wait()
	close(c.syncRequest)
}

func (c *Consumer[V]) process(cpu int, b *batch, syncing bool) {

	begin, end := c.offsets.Get(cpu, b, syncing)

	// telemetry stuff
	c.batchSize.Store(int64(b.Cap))
	c.eventsCount.Add(int64(end - begin))
	c.kernelDropsCount.Add(int64(b.Dropped_events))

	defer func() {
		if r := recover(); r != nil {
			log.Errorf("recovered from panic. begin=%d end=%d unsafe_event_size=%d batch_event_size=%d ", begin, end, int(unsafe.Sizeof(*new(V))), int(b.Event_size))
		}
	}()

	// generate a slice of type []V from the batch
	length := end - begin
	ptr := pointerToElement[V](b, begin)
	events := unsafe.Slice(ptr, length)

	c.callback(events)
}

func batchFromEventData(data []byte) (*batch, error) {
	if len(data) != sizeOfBatch {
		// for some reason the eBPF program sent us a perf event
		// that doesn't match what we're expecting
		return nil, errInvalidPerfEvent
	}

	return (*batch)(unsafe.Pointer(&data[0])), nil
}

func pointerToElement[V any](b *batch, elementIdx int) *V {
	offset := elementIdx * int(b.Event_size)
	return (*V)(unsafe.Pointer(uintptr(unsafe.Pointer(&b.Data[0])) + uintptr(offset)))
}
