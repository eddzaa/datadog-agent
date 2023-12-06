// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package writer

import (
	"compress/gzip"
	"errors"
	"runtime"
	"strings"
	"sync"
	"time"

	pb "github.com/DataDog/datadog-agent/pkg/proto/pbgo/trace"
	"github.com/DataDog/datadog-agent/pkg/trace/config"
	"github.com/DataDog/datadog-agent/pkg/trace/info"
	"github.com/DataDog/datadog-agent/pkg/trace/log"
	"github.com/DataDog/datadog-agent/pkg/trace/metrics"
	"github.com/DataDog/datadog-agent/pkg/trace/metrics/timing"
	"github.com/DataDog/datadog-agent/pkg/trace/telemetry"
	"github.com/DataDog/datadog-agent/pkg/trace/tracerpayload"
)

// pathTraces is the target host API path for delivering traces.
const pathTraces = "/api/v0.2/traces"

// MaxPayloadSize specifies the maximum accumulated payload size that is allowed before
// a flush is triggered; replaced in tests.
var MaxPayloadSize = 3200000 // 3.2MB is the maximum allowed by the Datadog API

type samplerTPSReader interface {
	GetTargetTPS() float64
}

type samplerEnabledReader interface {
	IsEnabled() bool
}

// SampledChunks represents the result of a trace sampling operation.
type SampledChunks struct {
	// TracerPayload contains all the chunks that were sampled as part of processing a payload.
	TracerPayload tracerpayload.Generic
	// Size represents the approximated message size in bytes.
	Size int
	// SpanCount specifies the number of spans that were sampled as part of a trace inside the TracerPayload.
	SpanCount int64
	// EventCount specifies the total number of events found in Traces.
	EventCount int64
}

// TraceWriter buffers traces and APM events, flushing them to the Datadog API.
type TraceWriter struct {
	// In receives sampled spans to be processed by the trace writer.
	// Channel should only be received from when testing.
	In        chan *SampledChunks
	Serialize chan *pb.AgentPayload
	// used to keep track of payloads currently being flushed
	// only useful for tests
	swg sync.WaitGroup

	prioritySampler samplerTPSReader
	errorsSampler   samplerTPSReader
	rareSampler     samplerEnabledReader

	hostname     string
	env          string
	senders      []*sender
	stop         chan struct{}
	stats        *info.TraceWriterInfo
	wg           sync.WaitGroup // waits for gzippers
	tick         time.Duration  // flush frequency
	agentVersion string

	tracerPayloads []tracerpayload.Generic // tracer payloads buffered
	bufferedSize   int                     // estimated buffer size

	// syncMode reports whether the writer should flush on its own or only when FlushSync is called
	syncMode  bool
	flushChan chan chan struct{}

	telemetryCollector telemetry.TelemetryCollector

	easylog *log.ThrottledLogger
}

// NewTraceWriter returns a new TraceWriter. It is created for the given agent configuration and
// will accept incoming spans via the in channel.
func NewTraceWriter(cfg *config.AgentConfig, prioritySampler samplerTPSReader, errorsSampler samplerTPSReader, rareSampler samplerEnabledReader, telemetryCollector telemetry.TelemetryCollector) *TraceWriter {
	tw := &TraceWriter{
		In:                 make(chan *SampledChunks, 1),
		Serialize:          make(chan *pb.AgentPayload, 1),
		prioritySampler:    prioritySampler,
		errorsSampler:      errorsSampler,
		rareSampler:        rareSampler,
		hostname:           cfg.Hostname,
		env:                cfg.DefaultEnv,
		stats:              &info.TraceWriterInfo{},
		stop:               make(chan struct{}),
		flushChan:          make(chan chan struct{}),
		syncMode:           cfg.SynchronousFlushing,
		tick:               5 * time.Second,
		agentVersion:       cfg.AgentVersion,
		easylog:            log.NewThrottled(5, 10*time.Second), // no more than 5 messages every 10 seconds
		telemetryCollector: telemetryCollector,
	}
	climit := cfg.TraceWriter.ConnectionLimit
	if climit == 0 {
		climit = 100
	}
	if cfg.TraceWriter.QueueSize > 0 {
		log.Warnf("apm_config.trace_writer.queue_size is deprecated and will not be respected.")
	}

	if s := cfg.TraceWriter.FlushPeriodSeconds; s != 0 {
		tw.tick = time.Duration(s*1000) * time.Millisecond
	}
	qsize := 1
	log.Warnf("Trace writer initialized (climit=%d qsize=%d)", climit, qsize)
	tw.senders = newSenders(cfg, tw, pathTraces, climit, qsize, telemetryCollector)
	for i := 0; i < runtime.GOMAXPROCS(0); i++ {
		tw.wg.Add(1)
		go tw.serializer()
	}
	return tw
}

// Stop stops the TraceWriter and attempts to flush whatever is left in the senders buffers.
func (w *TraceWriter) Stop() {
	log.Debug("Exiting trace writer. Trying to flush whatever is left...")
	w.stop <- struct{}{}
	<-w.stop
	// Wait for encoding/compression to complete on each payload,
	// and submission to senders
	w.wg.Wait()
	stopSenders(w.senders)
}

// Run starts the TraceWriter.
func (w *TraceWriter) Run() {
	if w.syncMode {
		w.runSync()
	} else {
		w.runAsync()
	}
}

func (w *TraceWriter) runAsync() {
	t := time.NewTicker(w.tick)
	defer t.Stop()
	defer close(w.Serialize)
	defer close(w.stop)
	for {
		select {
		case pkg := <-w.In:
			w.addSpans(pkg)
		case <-w.stop:
			w.drainAndFlush()
			return
		case <-t.C:
			w.report()
			w.flush()
		}
	}
}

func (w *TraceWriter) runSync() {
	defer close(w.Serialize)
	defer close(w.stop)
	defer close(w.flushChan)
	for {
		select {
		case pkg := <-w.In:
			w.addSpans(pkg)
		case notify := <-w.flushChan:
			w.drainAndFlush()
			notify <- struct{}{}
		case <-w.stop:
			w.drainAndFlush()
			return
		}
	}
}

// FlushSync blocks and sends pending payloads when syncMode is true
func (w *TraceWriter) FlushSync() error {
	if !w.syncMode {
		return errors.New("not flushing; sync mode not enabled")
	}
	defer w.report()

	notify := make(chan struct{}, 1)
	w.flushChan <- notify
	<-notify
	return nil
}

func (w *TraceWriter) addSpans(pkg *SampledChunks) {
	w.stats.Spans.Add(pkg.SpanCount)
	w.stats.Traces.Add(int64(pkg.TracerPayload.NumChunks()))
	w.stats.Events.Add(pkg.EventCount)

	size := pkg.Size
	if size+w.bufferedSize > MaxPayloadSize {
		// reached maximum allowed buffered size
		w.flush()
	}
	if pkg.TracerPayload.NumChunks() > 0 {
		log.Tracef("Writer: handling new tracer payload with %d spans: %v", pkg.SpanCount, pkg.TracerPayload)
		w.tracerPayloads = append(w.tracerPayloads, pkg.TracerPayload)
	}
	w.bufferedSize += size
}

func (w *TraceWriter) drainAndFlush() {
outer:
	for {
		select {
		case pkg := <-w.In:
			w.addSpans(pkg)
		default:
			break outer
		}
	}
	w.flush()
	w.swg.Wait()
}

func (w *TraceWriter) resetBuffer() {
	w.bufferedSize = 0
	w.tracerPayloads = make([]tracerpayload.Generic, 0, len(w.tracerPayloads))
}

const headerLanguages = "X-Datadog-Reported-Languages"

func (w *TraceWriter) flush() {
	if len(w.tracerPayloads) == 0 {
		// nothing to do
		return
	}

	defer timing.Since("datadog.trace_agent.trace_writer.encode_ms", time.Now())
	defer w.resetBuffer()

	log.Debugf("Serializing %d tracer payloads.", len(w.tracerPayloads))
	//TODO: this stinks to have to loop every payload, can we get around this
	pbTps := make([]*pb.TracerPayload, len(w.tracerPayloads))
	for i, tp := range w.tracerPayloads {
		pbTps[i] = tp.ToPb()
	}
	p := pb.AgentPayload{
		AgentVersion:       w.agentVersion,
		HostName:           w.hostname,
		Env:                w.env,
		TargetTPS:          w.prioritySampler.GetTargetTPS(),
		ErrorTPS:           w.errorsSampler.GetTargetTPS(),
		RareSamplerEnabled: w.rareSampler.IsEnabled(),
		TracerPayloads:     pbTps,
	}
	log.Debugf("Reported agent rates: target_tps=%v errors_tps=%v rare_sampling=%v", p.TargetTPS, p.ErrorTPS, p.RareSamplerEnabled)

	w.swg.Add(1)
	w.Serialize <- &p
}

func (w *TraceWriter) serializer() {
	defer w.wg.Done()
	for pl := range w.Serialize {
		func() {
			defer w.swg.Done()
			b, err := pl.MarshalVT()
			if err != nil {
				log.Errorf("Failed to serialize payload, data dropped: %v", err)
				return
			}

			w.stats.BytesUncompressed.Add(int64(len(b)))
			p := newPayload(map[string]string{
				"Content-Type":     "application/x-protobuf",
				"Content-Encoding": "gzip",
				headerLanguages:    strings.Join(info.Languages(), "|"),
			})
			gzipw, err := gzip.NewWriterLevel(p.body, gzip.BestSpeed)
			if err != nil {
				// it will never happen, unless an invalid compression is chosen;
				// we know gzip.BestSpeed is valid.
				log.Errorf("gzip.NewWriterLevel: %d", err)
				return
			}
			if _, err := gzipw.Write(b); err != nil {
				log.Errorf("Error gzipping trace payload: %v", err)
			}
			if err := gzipw.Close(); err != nil {
				log.Errorf("Error closing gzip stream when writing trace payload: %v", err)
			}
			sendPayloads(w.senders, p, w.syncMode)
		}()
	}
}

func (w *TraceWriter) report() {
	metrics.Count("datadog.trace_agent.trace_writer.payloads", w.stats.Payloads.Swap(0), nil, 1)
	metrics.Count("datadog.trace_agent.trace_writer.bytes_uncompressed", w.stats.BytesUncompressed.Swap(0), nil, 1)
	metrics.Count("datadog.trace_agent.trace_writer.retries", w.stats.Retries.Swap(0), nil, 1)
	metrics.Count("datadog.trace_agent.trace_writer.bytes", w.stats.Bytes.Swap(0), nil, 1)
	metrics.Count("datadog.trace_agent.trace_writer.errors", w.stats.Errors.Swap(0), nil, 1)
	metrics.Count("datadog.trace_agent.trace_writer.traces", w.stats.Traces.Swap(0), nil, 1)
	metrics.Count("datadog.trace_agent.trace_writer.events", w.stats.Events.Swap(0), nil, 1)
	metrics.Count("datadog.trace_agent.trace_writer.spans", w.stats.Spans.Swap(0), nil, 1)
}

var _ eventRecorder = (*TraceWriter)(nil)

// recordEvent implements eventRecorder.
func (w *TraceWriter) recordEvent(t eventType, data *eventData) {
	if data != nil {
		metrics.Histogram("datadog.trace_agent.trace_writer.connection_fill", data.connectionFill, nil, 1)
		metrics.Histogram("datadog.trace_agent.trace_writer.queue_fill", data.queueFill, nil, 1)
	}
	switch t {
	case eventTypeRetry:
		log.Debugf("Retrying to flush trace payload; error: %s", data.err)
		w.stats.Retries.Inc()

	case eventTypeSent:
		log.Debugf("Flushed traces to the API; time: %s, bytes: %d", data.duration, data.bytes)
		timing.Since("datadog.trace_agent.trace_writer.flush_duration", time.Now().Add(-data.duration))
		w.stats.Bytes.Add(int64(data.bytes))
		w.stats.Payloads.Inc()
		if !w.telemetryCollector.SentFirstTrace() {
			go w.telemetryCollector.SendFirstTrace()
		}

	case eventTypeRejected:
		log.Warnf("Trace writer payload rejected by edge: %v", data.err)
		w.stats.Errors.Inc()

	case eventTypeDropped:
		w.easylog.Warn("Trace Payload dropped (%.2fKB).", float64(data.bytes)/1024)
		metrics.Count("datadog.trace_agent.trace_writer.dropped", 1, nil, 1)
		metrics.Count("datadog.trace_agent.trace_writer.dropped_bytes", int64(data.bytes), nil, 1)
	}
}
