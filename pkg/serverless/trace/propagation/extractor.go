package propagation

import (
	"errors"

	"github.com/DataDog/datadog-agent/pkg/trace/sampler"
	"github.com/aws/aws-lambda-go/events"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace"
	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace/tracer"
)

const defaultPriority sampler.SamplingPriority = 0

type Extractor struct {
	propagator tracer.Propagator
}

type TraceContext struct {
	TraceID  uint64
	ParentID uint64
	Priority sampler.SamplingPriority
}

func NewExtractor() Extractor {
	prop := tracer.NewPropagator(nil)
	return Extractor{
		propagator: prop,
	}
}

func (e *Extractor) Extract(event interface{}) (*TraceContext, error) {
	if e == nil {
		return nil, errors.New("Extraction not configured")
	}
	var carrier tracer.TextMapReader
	var err error
	switch ev := event.(type) {
	case events.SQSMessage:
		if attr, ok := ev.Attributes[awsTraceHeader]; ok {
			if tc, err := extractTraceContextfromAWSTraceHeader(attr); err == nil {
				// Return early if AWSTraceHeader contains trace context
				return tc, nil
			}
		}
		carrier, err = sqsMessageCarrier(ev)
	default:
		err = errors.New("Unsupported event type for trace context extraction")
	}
	if err != nil {
		return nil, err
	}
	sc, err := e.propagator.Extract(carrier)
	if err != nil {
		return nil, err
	}
	return &TraceContext{
		TraceID:  sc.TraceID(),
		ParentID: sc.SpanID(),
		Priority: getPriority(sc),
	}, nil
}

func getPriority(sc ddtrace.SpanContext) (priority sampler.SamplingPriority) {
	priority = defaultPriority
	if pc, ok := sc.(interface{ SamplingPriority() (int, bool) }); ok {
		if p, ok := pc.SamplingPriority(); ok {
			priority = sampler.SamplingPriority(p)
		}
	}
	return
}
