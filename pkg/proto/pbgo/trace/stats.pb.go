// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.25.3
// source: datadog/trace/stats.proto

package trace

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// StatsPayload is the payload used to send stats from the agent to the backend.
type StatsPayload struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AgentHostname string `protobuf:"bytes,1,opt,name=agentHostname,proto3" json:"agentHostname,omitempty"`
	AgentEnv      string `protobuf:"bytes,2,opt,name=agentEnv,proto3" json:"agentEnv,omitempty"`
	// @gotags: json:"stats,omitempty" msg:"Stats,omitempty"
	Stats          []*ClientStatsPayload `protobuf:"bytes,3,rep,name=stats,proto3" json:"stats,omitempty" msg:"Stats,omitempty"`
	AgentVersion   string                `protobuf:"bytes,4,opt,name=agentVersion,proto3" json:"agentVersion,omitempty"`
	ClientComputed bool                  `protobuf:"varint,5,opt,name=clientComputed,proto3" json:"clientComputed,omitempty"`
	// splitPayload indicates if the payload is actually one of several payloads split out from a larger payload.
	// This field can be used in the backend to signal if re-aggregation is necessary.
	SplitPayload bool `protobuf:"varint,6,opt,name=splitPayload,proto3" json:"splitPayload,omitempty"`
}

func (x *StatsPayload) Reset() {
	*x = StatsPayload{}
	if protoimpl.UnsafeEnabled {
		mi := &file_datadog_trace_stats_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StatsPayload) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StatsPayload) ProtoMessage() {}

func (x *StatsPayload) ProtoReflect() protoreflect.Message {
	mi := &file_datadog_trace_stats_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StatsPayload.ProtoReflect.Descriptor instead.
func (*StatsPayload) Descriptor() ([]byte, []int) {
	return file_datadog_trace_stats_proto_rawDescGZIP(), []int{0}
}

func (x *StatsPayload) GetAgentHostname() string {
	if x != nil {
		return x.AgentHostname
	}
	return ""
}

func (x *StatsPayload) GetAgentEnv() string {
	if x != nil {
		return x.AgentEnv
	}
	return ""
}

func (x *StatsPayload) GetStats() []*ClientStatsPayload {
	if x != nil {
		return x.Stats
	}
	return nil
}

func (x *StatsPayload) GetAgentVersion() string {
	if x != nil {
		return x.AgentVersion
	}
	return ""
}

func (x *StatsPayload) GetClientComputed() bool {
	if x != nil {
		return x.ClientComputed
	}
	return false
}

func (x *StatsPayload) GetSplitPayload() bool {
	if x != nil {
		return x.SplitPayload
	}
	return false
}

// ClientStatsPayload is the first layer of span stats aggregation. It is also
// the payload sent by tracers to the agent when stats in tracer are enabled.
type ClientStatsPayload struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Hostname is the tracer hostname. It's extracted from spans with "_dd.hostname" meta
	// or set by tracer stats payload when hostname reporting is enabled.
	Hostname string `protobuf:"bytes,1,opt,name=hostname,proto3" json:"hostname,omitempty"`
	Env      string `protobuf:"bytes,2,opt,name=env,proto3" json:"env,omitempty"`         // env tag set on spans or in the tracers, used for aggregation
	Version  string `protobuf:"bytes,3,opt,name=version,proto3" json:"version,omitempty"` // version tag set on spans or in the tracers, used for aggregation
	// @gotags: json:"stats,omitempty" msg:"Stats,omitempty"
	Stats         []*ClientStatsBucket `protobuf:"bytes,4,rep,name=stats,proto3" json:"stats,omitempty" msg:"Stats,omitempty"`
	Lang          string               `protobuf:"bytes,5,opt,name=lang,proto3" json:"lang,omitempty"`                   // informative field not used for aggregation
	TracerVersion string               `protobuf:"bytes,6,opt,name=tracerVersion,proto3" json:"tracerVersion,omitempty"` // informative field not used for aggregation
	RuntimeID     string               `protobuf:"bytes,7,opt,name=runtimeID,proto3" json:"runtimeID,omitempty"`         // used on stats payloads sent by the tracer to identify uniquely a message
	Sequence      uint64               `protobuf:"varint,8,opt,name=sequence,proto3" json:"sequence,omitempty"`          // used on stats payloads sent by the tracer to identify uniquely a message
	// AgentAggregation is set by the agent on tracer payloads modified by the agent aggregation layer
	// characterizes counts only and distributions only payloads
	AgentAggregation string `protobuf:"bytes,9,opt,name=agentAggregation,proto3" json:"agentAggregation,omitempty"`
	// Service is the main service of the tracer.
	// It is part of unified tagging: https://docs.datadoghq.com/getting_started/tagging/unified_service_tagging
	Service string `protobuf:"bytes,10,opt,name=service,proto3" json:"service,omitempty"`
	// ContainerID specifies the origin container ID. It is meant to be populated by the client and may
	// be enhanced by the agent to ensure it is unique.
	ContainerID string `protobuf:"bytes,11,opt,name=containerID,proto3" json:"containerID,omitempty"`
	// Tags specifies a set of tags obtained from the orchestrator (where applicable) using the specified containerID.
	// This field should be left empty by the client. It only applies to some specific environment.
	Tags []string `protobuf:"bytes,12,rep,name=tags,proto3" json:"tags,omitempty"`
	// The git commit SHA is obtained from a trace, where it may be set through a tracer <-> source code integration.
	GitCommitSha string `protobuf:"bytes,13,opt,name=git_commit_sha,json=gitCommitSha,proto3" json:"git_commit_sha,omitempty"`
	// The image tag is obtained from a container's set of tags.
	ImageTag string `protobuf:"bytes,14,opt,name=image_tag,json=imageTag,proto3" json:"image_tag,omitempty"`
}

func (x *ClientStatsPayload) Reset() {
	*x = ClientStatsPayload{}
	if protoimpl.UnsafeEnabled {
		mi := &file_datadog_trace_stats_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ClientStatsPayload) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientStatsPayload) ProtoMessage() {}

func (x *ClientStatsPayload) ProtoReflect() protoreflect.Message {
	mi := &file_datadog_trace_stats_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientStatsPayload.ProtoReflect.Descriptor instead.
func (*ClientStatsPayload) Descriptor() ([]byte, []int) {
	return file_datadog_trace_stats_proto_rawDescGZIP(), []int{1}
}

func (x *ClientStatsPayload) GetHostname() string {
	if x != nil {
		return x.Hostname
	}
	return ""
}

func (x *ClientStatsPayload) GetEnv() string {
	if x != nil {
		return x.Env
	}
	return ""
}

func (x *ClientStatsPayload) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *ClientStatsPayload) GetStats() []*ClientStatsBucket {
	if x != nil {
		return x.Stats
	}
	return nil
}

func (x *ClientStatsPayload) GetLang() string {
	if x != nil {
		return x.Lang
	}
	return ""
}

func (x *ClientStatsPayload) GetTracerVersion() string {
	if x != nil {
		return x.TracerVersion
	}
	return ""
}

func (x *ClientStatsPayload) GetRuntimeID() string {
	if x != nil {
		return x.RuntimeID
	}
	return ""
}

func (x *ClientStatsPayload) GetSequence() uint64 {
	if x != nil {
		return x.Sequence
	}
	return 0
}

func (x *ClientStatsPayload) GetAgentAggregation() string {
	if x != nil {
		return x.AgentAggregation
	}
	return ""
}

func (x *ClientStatsPayload) GetService() string {
	if x != nil {
		return x.Service
	}
	return ""
}

func (x *ClientStatsPayload) GetContainerID() string {
	if x != nil {
		return x.ContainerID
	}
	return ""
}

func (x *ClientStatsPayload) GetTags() []string {
	if x != nil {
		return x.Tags
	}
	return nil
}

func (x *ClientStatsPayload) GetGitCommitSha() string {
	if x != nil {
		return x.GitCommitSha
	}
	return ""
}

func (x *ClientStatsPayload) GetImageTag() string {
	if x != nil {
		return x.ImageTag
	}
	return ""
}

// ClientStatsBucket is a time bucket containing aggregated stats.
type ClientStatsBucket struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Start    uint64 `protobuf:"varint,1,opt,name=start,proto3" json:"start,omitempty"`       // bucket start in nanoseconds
	Duration uint64 `protobuf:"varint,2,opt,name=duration,proto3" json:"duration,omitempty"` // bucket duration in nanoseconds
	// @gotags: json:"stats,omitempty" msg:"Stats,omitempty"
	Stats []*ClientGroupedStats `protobuf:"bytes,3,rep,name=stats,proto3" json:"stats,omitempty" msg:"Stats,omitempty"`
	// AgentTimeShift is the shift applied by the agent stats aggregator on bucket start
	// when the received bucket start is outside of the agent aggregation window
	AgentTimeShift int64 `protobuf:"varint,4,opt,name=agentTimeShift,proto3" json:"agentTimeShift,omitempty"`
}

func (x *ClientStatsBucket) Reset() {
	*x = ClientStatsBucket{}
	if protoimpl.UnsafeEnabled {
		mi := &file_datadog_trace_stats_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ClientStatsBucket) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientStatsBucket) ProtoMessage() {}

func (x *ClientStatsBucket) ProtoReflect() protoreflect.Message {
	mi := &file_datadog_trace_stats_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientStatsBucket.ProtoReflect.Descriptor instead.
func (*ClientStatsBucket) Descriptor() ([]byte, []int) {
	return file_datadog_trace_stats_proto_rawDescGZIP(), []int{2}
}

func (x *ClientStatsBucket) GetStart() uint64 {
	if x != nil {
		return x.Start
	}
	return 0
}

func (x *ClientStatsBucket) GetDuration() uint64 {
	if x != nil {
		return x.Duration
	}
	return 0
}

func (x *ClientStatsBucket) GetStats() []*ClientGroupedStats {
	if x != nil {
		return x.Stats
	}
	return nil
}

func (x *ClientStatsBucket) GetAgentTimeShift() int64 {
	if x != nil {
		return x.AgentTimeShift
	}
	return 0
}

// ClientGroupedStats aggregate stats on spans grouped by service, name, resource, status_code, type
type ClientGroupedStats struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Service        string `protobuf:"bytes,1,opt,name=service,proto3" json:"service,omitempty"`
	Name           string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Resource       string `protobuf:"bytes,3,opt,name=resource,proto3" json:"resource,omitempty"`
	HTTPStatusCode uint32 `protobuf:"varint,4,opt,name=HTTP_status_code,json=HTTPStatusCode,proto3" json:"HTTP_status_code,omitempty"`
	Type           string `protobuf:"bytes,5,opt,name=type,proto3" json:"type,omitempty"`
	DBType         string `protobuf:"bytes,6,opt,name=DB_type,json=DBType,proto3" json:"DB_type,omitempty"`        // db_type might be used in the future to help in the obfuscation step
	Hits           uint64 `protobuf:"varint,7,opt,name=hits,proto3" json:"hits,omitempty"`                         // count of all spans aggregated in the groupedstats
	Errors         uint64 `protobuf:"varint,8,opt,name=errors,proto3" json:"errors,omitempty"`                     // count of error spans aggregated in the groupedstats
	Duration       uint64 `protobuf:"varint,9,opt,name=duration,proto3" json:"duration,omitempty"`                 // total duration in nanoseconds of spans aggregated in the bucket
	OkSummary      []byte `protobuf:"bytes,10,opt,name=okSummary,proto3" json:"okSummary,omitempty"`               // ddsketch summary of ok spans latencies encoded in protobuf
	ErrorSummary   []byte `protobuf:"bytes,11,opt,name=errorSummary,proto3" json:"errorSummary,omitempty"`         // ddsketch summary of error spans latencies encoded in protobuf
	Synthetics     bool   `protobuf:"varint,12,opt,name=synthetics,proto3" json:"synthetics,omitempty"`            // set to true on spans generated by synthetics traffic
	TopLevelHits   uint64 `protobuf:"varint,13,opt,name=topLevelHits,proto3" json:"topLevelHits,omitempty"`        // count of top level spans aggregated in the groupedstats
	SpanKind       string `protobuf:"bytes,15,opt,name=span_kind,json=spanKind,proto3" json:"span_kind,omitempty"` // value of the span.kind tag on the span
	// peer_tags are supplementary tags that further describe a peer entity
	// E.g., `grpc.target` to describe the name of a gRPC peer, or `db.hostname` to describe the name of peer DB
	PeerTags     []string `protobuf:"bytes,16,rep,name=peer_tags,json=peerTags,proto3" json:"peer_tags,omitempty"`
	IsParentRoot bool     `protobuf:"varint,17,opt,name=is_parent_root,json=isParentRoot,proto3" json:"is_parent_root,omitempty"` // this field's value is equal to span's ParentID == 0.
}

func (x *ClientGroupedStats) Reset() {
	*x = ClientGroupedStats{}
	if protoimpl.UnsafeEnabled {
		mi := &file_datadog_trace_stats_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ClientGroupedStats) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ClientGroupedStats) ProtoMessage() {}

func (x *ClientGroupedStats) ProtoReflect() protoreflect.Message {
	mi := &file_datadog_trace_stats_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ClientGroupedStats.ProtoReflect.Descriptor instead.
func (*ClientGroupedStats) Descriptor() ([]byte, []int) {
	return file_datadog_trace_stats_proto_rawDescGZIP(), []int{3}
}

func (x *ClientGroupedStats) GetService() string {
	if x != nil {
		return x.Service
	}
	return ""
}

func (x *ClientGroupedStats) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *ClientGroupedStats) GetResource() string {
	if x != nil {
		return x.Resource
	}
	return ""
}

func (x *ClientGroupedStats) GetHTTPStatusCode() uint32 {
	if x != nil {
		return x.HTTPStatusCode
	}
	return 0
}

func (x *ClientGroupedStats) GetType() string {
	if x != nil {
		return x.Type
	}
	return ""
}

func (x *ClientGroupedStats) GetDBType() string {
	if x != nil {
		return x.DBType
	}
	return ""
}

func (x *ClientGroupedStats) GetHits() uint64 {
	if x != nil {
		return x.Hits
	}
	return 0
}

func (x *ClientGroupedStats) GetErrors() uint64 {
	if x != nil {
		return x.Errors
	}
	return 0
}

func (x *ClientGroupedStats) GetDuration() uint64 {
	if x != nil {
		return x.Duration
	}
	return 0
}

func (x *ClientGroupedStats) GetOkSummary() []byte {
	if x != nil {
		return x.OkSummary
	}
	return nil
}

func (x *ClientGroupedStats) GetErrorSummary() []byte {
	if x != nil {
		return x.ErrorSummary
	}
	return nil
}

func (x *ClientGroupedStats) GetSynthetics() bool {
	if x != nil {
		return x.Synthetics
	}
	return false
}

func (x *ClientGroupedStats) GetTopLevelHits() uint64 {
	if x != nil {
		return x.TopLevelHits
	}
	return 0
}

func (x *ClientGroupedStats) GetSpanKind() string {
	if x != nil {
		return x.SpanKind
	}
	return ""
}

func (x *ClientGroupedStats) GetPeerTags() []string {
	if x != nil {
		return x.PeerTags
	}
	return nil
}

func (x *ClientGroupedStats) GetIsParentRoot() bool {
	if x != nil {
		return x.IsParentRoot
	}
	return false
}

var File_datadog_trace_stats_proto protoreflect.FileDescriptor

var file_datadog_trace_stats_proto_rawDesc = []byte{
	0x0a, 0x19, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2f,
	0x73, 0x74, 0x61, 0x74, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0d, 0x64, 0x61, 0x74,
	0x61, 0x64, 0x6f, 0x67, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x22, 0xf9, 0x01, 0x0a, 0x0c, 0x53,
	0x74, 0x61, 0x74, 0x73, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x24, 0x0a, 0x0d, 0x61,
	0x67, 0x65, 0x6e, 0x74, 0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0d, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x48, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d,
	0x65, 0x12, 0x1a, 0x0a, 0x08, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x45, 0x6e, 0x76, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x08, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x45, 0x6e, 0x76, 0x12, 0x37, 0x0a,
	0x05, 0x73, 0x74, 0x61, 0x74, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x64,
	0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2e, 0x43, 0x6c, 0x69,
	0x65, 0x6e, 0x74, 0x53, 0x74, 0x61, 0x74, 0x73, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x52,
	0x05, 0x73, 0x74, 0x61, 0x74, 0x73, 0x12, 0x22, 0x0a, 0x0c, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x56,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x61, 0x67,
	0x65, 0x6e, 0x74, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x26, 0x0a, 0x0e, 0x63, 0x6c,
	0x69, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x64, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x0e, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74,
	0x65, 0x64, 0x12, 0x22, 0x0a, 0x0c, 0x73, 0x70, 0x6c, 0x69, 0x74, 0x50, 0x61, 0x79, 0x6c, 0x6f,
	0x61, 0x64, 0x18, 0x06, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0c, 0x73, 0x70, 0x6c, 0x69, 0x74, 0x50,
	0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x22, 0xc7, 0x03, 0x0a, 0x12, 0x43, 0x6c, 0x69, 0x65, 0x6e,
	0x74, 0x53, 0x74, 0x61, 0x74, 0x73, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x1a, 0x0a,
	0x08, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x08, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x65, 0x6e, 0x76,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x65, 0x6e, 0x76, 0x12, 0x18, 0x0a, 0x07, 0x76,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x76, 0x65,
	0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x36, 0x0a, 0x05, 0x73, 0x74, 0x61, 0x74, 0x73, 0x18, 0x04,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f, 0x67, 0x2e, 0x74,
	0x72, 0x61, 0x63, 0x65, 0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x53, 0x74, 0x61, 0x74, 0x73,
	0x42, 0x75, 0x63, 0x6b, 0x65, 0x74, 0x52, 0x05, 0x73, 0x74, 0x61, 0x74, 0x73, 0x12, 0x12, 0x0a,
	0x04, 0x6c, 0x61, 0x6e, 0x67, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6c, 0x61, 0x6e,
	0x67, 0x12, 0x24, 0x0a, 0x0d, 0x74, 0x72, 0x61, 0x63, 0x65, 0x72, 0x56, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x74, 0x72, 0x61, 0x63, 0x65, 0x72,
	0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x1c, 0x0a, 0x09, 0x72, 0x75, 0x6e, 0x74, 0x69,
	0x6d, 0x65, 0x49, 0x44, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x72, 0x75, 0x6e, 0x74,
	0x69, 0x6d, 0x65, 0x49, 0x44, 0x12, 0x1a, 0x0a, 0x08, 0x73, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63,
	0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x04, 0x52, 0x08, 0x73, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63,
	0x65, 0x12, 0x2a, 0x0a, 0x10, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x41, 0x67, 0x67, 0x72, 0x65, 0x67,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x10, 0x61, 0x67, 0x65,
	0x6e, 0x74, 0x41, 0x67, 0x67, 0x72, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x18, 0x0a,
	0x07, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x20, 0x0a, 0x0b, 0x63, 0x6f, 0x6e, 0x74, 0x61,
	0x69, 0x6e, 0x65, 0x72, 0x49, 0x44, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x63, 0x6f,
	0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x49, 0x44, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x61, 0x67,
	0x73, 0x18, 0x0c, 0x20, 0x03, 0x28, 0x09, 0x52, 0x04, 0x74, 0x61, 0x67, 0x73, 0x12, 0x24, 0x0a,
	0x0e, 0x67, 0x69, 0x74, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x5f, 0x73, 0x68, 0x61, 0x18,
	0x0d, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x67, 0x69, 0x74, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74,
	0x53, 0x68, 0x61, 0x12, 0x1b, 0x0a, 0x09, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x5f, 0x74, 0x61, 0x67,
	0x18, 0x0e, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x54, 0x61, 0x67,
	0x22, 0xa6, 0x01, 0x0a, 0x11, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x53, 0x74, 0x61, 0x74, 0x73,
	0x42, 0x75, 0x63, 0x6b, 0x65, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x74, 0x61, 0x72, 0x74, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x05, 0x73, 0x74, 0x61, 0x72, 0x74, 0x12, 0x1a, 0x0a, 0x08,
	0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x08,
	0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x37, 0x0a, 0x05, 0x73, 0x74, 0x61, 0x74,
	0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x64, 0x61, 0x74, 0x61, 0x64, 0x6f,
	0x67, 0x2e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x2e, 0x43, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x47, 0x72,
	0x6f, 0x75, 0x70, 0x65, 0x64, 0x53, 0x74, 0x61, 0x74, 0x73, 0x52, 0x05, 0x73, 0x74, 0x61, 0x74,
	0x73, 0x12, 0x26, 0x0a, 0x0e, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x54, 0x69, 0x6d, 0x65, 0x53, 0x68,
	0x69, 0x66, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0e, 0x61, 0x67, 0x65, 0x6e, 0x74,
	0x54, 0x69, 0x6d, 0x65, 0x53, 0x68, 0x69, 0x66, 0x74, 0x22, 0xe9, 0x03, 0x0a, 0x12, 0x43, 0x6c,
	0x69, 0x65, 0x6e, 0x74, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x65, 0x64, 0x53, 0x74, 0x61, 0x74, 0x73,
	0x12, 0x18, 0x0a, 0x07, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1a,
	0x0a, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x28, 0x0a, 0x10, 0x48, 0x54,
	0x54, 0x50, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x5f, 0x63, 0x6f, 0x64, 0x65, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0d, 0x52, 0x0e, 0x48, 0x54, 0x54, 0x50, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73,
	0x43, 0x6f, 0x64, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x17, 0x0a, 0x07, 0x44, 0x42, 0x5f, 0x74,
	0x79, 0x70, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x44, 0x42, 0x54, 0x79, 0x70,
	0x65, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x69, 0x74, 0x73, 0x18, 0x07, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x04, 0x68, 0x69, 0x74, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x73, 0x18,
	0x08, 0x20, 0x01, 0x28, 0x04, 0x52, 0x06, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x73, 0x12, 0x1a, 0x0a,
	0x08, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x09, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x08, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1c, 0x0a, 0x09, 0x6f, 0x6b, 0x53,
	0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x6f, 0x6b,
	0x53, 0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79, 0x12, 0x22, 0x0a, 0x0c, 0x65, 0x72, 0x72, 0x6f, 0x72,
	0x53, 0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0c, 0x65,
	0x72, 0x72, 0x6f, 0x72, 0x53, 0x75, 0x6d, 0x6d, 0x61, 0x72, 0x79, 0x12, 0x1e, 0x0a, 0x0a, 0x73,
	0x79, 0x6e, 0x74, 0x68, 0x65, 0x74, 0x69, 0x63, 0x73, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x0a, 0x73, 0x79, 0x6e, 0x74, 0x68, 0x65, 0x74, 0x69, 0x63, 0x73, 0x12, 0x22, 0x0a, 0x0c, 0x74,
	0x6f, 0x70, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x48, 0x69, 0x74, 0x73, 0x18, 0x0d, 0x20, 0x01, 0x28,
	0x04, 0x52, 0x0c, 0x74, 0x6f, 0x70, 0x4c, 0x65, 0x76, 0x65, 0x6c, 0x48, 0x69, 0x74, 0x73, 0x12,
	0x1b, 0x0a, 0x09, 0x73, 0x70, 0x61, 0x6e, 0x5f, 0x6b, 0x69, 0x6e, 0x64, 0x18, 0x0f, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x08, 0x73, 0x70, 0x61, 0x6e, 0x4b, 0x69, 0x6e, 0x64, 0x12, 0x1b, 0x0a, 0x09,
	0x70, 0x65, 0x65, 0x72, 0x5f, 0x74, 0x61, 0x67, 0x73, 0x18, 0x10, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x08, 0x70, 0x65, 0x65, 0x72, 0x54, 0x61, 0x67, 0x73, 0x12, 0x24, 0x0a, 0x0e, 0x69, 0x73, 0x5f,
	0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x5f, 0x72, 0x6f, 0x6f, 0x74, 0x18, 0x11, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x0c, 0x69, 0x73, 0x50, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x52, 0x6f, 0x6f, 0x74, 0x4a,
	0x04, 0x08, 0x0e, 0x10, 0x0f, 0x42, 0x16, 0x5a, 0x14, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2f, 0x70, 0x62, 0x67, 0x6f, 0x2f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_datadog_trace_stats_proto_rawDescOnce sync.Once
	file_datadog_trace_stats_proto_rawDescData = file_datadog_trace_stats_proto_rawDesc
)

func file_datadog_trace_stats_proto_rawDescGZIP() []byte {
	file_datadog_trace_stats_proto_rawDescOnce.Do(func() {
		file_datadog_trace_stats_proto_rawDescData = protoimpl.X.CompressGZIP(file_datadog_trace_stats_proto_rawDescData)
	})
	return file_datadog_trace_stats_proto_rawDescData
}

var file_datadog_trace_stats_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_datadog_trace_stats_proto_goTypes = []interface{}{
	(*StatsPayload)(nil),       // 0: datadog.trace.StatsPayload
	(*ClientStatsPayload)(nil), // 1: datadog.trace.ClientStatsPayload
	(*ClientStatsBucket)(nil),  // 2: datadog.trace.ClientStatsBucket
	(*ClientGroupedStats)(nil), // 3: datadog.trace.ClientGroupedStats
}
var file_datadog_trace_stats_proto_depIdxs = []int32{
	1, // 0: datadog.trace.StatsPayload.stats:type_name -> datadog.trace.ClientStatsPayload
	2, // 1: datadog.trace.ClientStatsPayload.stats:type_name -> datadog.trace.ClientStatsBucket
	3, // 2: datadog.trace.ClientStatsBucket.stats:type_name -> datadog.trace.ClientGroupedStats
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_datadog_trace_stats_proto_init() }
func file_datadog_trace_stats_proto_init() {
	if File_datadog_trace_stats_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_datadog_trace_stats_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StatsPayload); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_datadog_trace_stats_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ClientStatsPayload); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_datadog_trace_stats_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ClientStatsBucket); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_datadog_trace_stats_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ClientGroupedStats); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_datadog_trace_stats_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_datadog_trace_stats_proto_goTypes,
		DependencyIndexes: file_datadog_trace_stats_proto_depIdxs,
		MessageInfos:      file_datadog_trace_stats_proto_msgTypes,
	}.Build()
	File_datadog_trace_stats_proto = out.File
	file_datadog_trace_stats_proto_rawDesc = nil
	file_datadog_trace_stats_proto_goTypes = nil
	file_datadog_trace_stats_proto_depIdxs = nil
}
