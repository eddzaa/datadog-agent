// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package http2

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/DataDog/datadog-agent/pkg/network/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/protocols"
	"github.com/DataDog/datadog-agent/pkg/network/protocols/http"
	"github.com/DataDog/datadog-agent/pkg/network/types"
	"github.com/DataDog/datadog-agent/pkg/process/util"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

var oversizedLogLimit = util.NewLogLimit(10, time.Minute*10)

func flipTuple(t connTuple) connTuple {
	return connTuple{
		Saddr_h:  t.Daddr_h,
		Saddr_l:  t.Daddr_l,
		Daddr_h:  t.Saddr_h,
		Daddr_l:  t.Saddr_l,
		Sport:    t.Dport,
		Dport:    t.Sport,
		Netns:    t.Netns,
		Pid:      t.Pid,
		Metadata: t.Metadata,
	}
}

// interestingValue represents a valuable header (static or dynamic) for the HTTP2 monitoring. It is either a path,
// a method, or a status code. It can be malformed if we're unable to resolve it in case of a dynamic value, or if the
// static table entry does not match to the predefined allowed list.
type interestingValue[V any] struct {
	value     V
	malformed bool
}

// validatePath validates the given path.
func validatePath(str string) error {
	if len(str) == 0 {
		return errors.New("decoded path is empty")
	}
	// ensure we found a '/' at the beginning of the path
	if str[0] != '/' {
		return fmt.Errorf("decoded path '%s' doesn't start with '/'", str)
	}
	return nil
}

// ebpfTXWrapper is a wrapper around the eBPF transaction.
// It extends the basic type with a pointer to an interned string, which will be filled by processHTTP2 method.
type ebpfTXWrapper struct {
	*EbpfTx
	dynamicTable *DynamicTable
	method       interestingValue[http.Method]
	path         interestingValue[string]
}

func (tx *ebpfTXWrapper) resolvePath() bool {
	if tx.path.malformed {
		return false
	}
	if tx.path.value != "" {
		return true
	}

	if tx.Stream.Path.Index <= http2staticTableMaxEntry {
		switch uint8(tx.Stream.Path.Index) {
		case EmptyPathValue:
			tx.path.value = "/"
		case IndexPathValue:
			tx.path.value = "/index.html"
		default:
			tx.path.malformed = true
		}
		return !tx.path.malformed
	}

	tup := tx.Tuple
	// TODO: Support flipped tuples.

	path, exists := tx.dynamicTable.resolveValue(tup, tx.Stream.Path.Index, tx.Stream.Path.Temporary)
	if !exists {
		return false
	}
	if err := validatePath(path); err != nil {
		if oversizedLogLimit.ShouldLog() {
			log.Warnf("path %s is invalid due to: %s", path, err)
		}
		tx.path.malformed = true
	} else {
		tx.path.value = path
	}
	return !tx.path.malformed
}

// Path returns the URL from the request fragment captured in eBPF.
func (tx *ebpfTXWrapper) Path(buffer []byte) ([]byte, bool) {
	if tx.resolvePath() {
		n := copy(buffer, tx.path.value)
		return buffer[:n], true
	}
	return nil, false
}

// RequestLatency returns the latency of the request in nanoseconds
func (tx *ebpfTXWrapper) RequestLatency() float64 {
	if uint64(tx.Stream.Request_started) == 0 || uint64(tx.Stream.Response_last_seen) == 0 {
		return 0
	}
	return protocols.NSTimestampToFloat(tx.Stream.Response_last_seen - tx.Stream.Request_started)
}

// Incomplete returns true if the transaction contains only the request or response information
// This happens in the context of localhost with NAT, in which case we join the two parts in userspace
func (tx *ebpfTXWrapper) Incomplete() bool {
	return tx.Stream.Request_started == 0 || tx.Stream.Response_last_seen == 0 || tx.StatusCode() == 0 || !tx.resolvePath() || !tx.resolveMethod()
}

// ConnTuple returns the connections tuple of the transaction.
func (tx *ebpfTXWrapper) ConnTuple() types.ConnectionKey {
	return types.ConnectionKey{
		SrcIPHigh: tx.Tuple.Saddr_h,
		SrcIPLow:  tx.Tuple.Saddr_l,
		DstIPHigh: tx.Tuple.Daddr_h,
		DstIPLow:  tx.Tuple.Daddr_l,
		SrcPort:   tx.Tuple.Sport,
		DstPort:   tx.Tuple.Dport,
	}
}

// stringToHTTPMethod converts a string to an HTTP method.
func stringToHTTPMethod(method string) (http.Method, error) {
	switch strings.ToUpper(method) {
	case "PUT":
		return http.MethodPut, nil
	case "DELETE":
		return http.MethodDelete, nil
	case "HEAD":
		return http.MethodHead, nil
	case "OPTIONS":
		return http.MethodOptions, nil
	case "PATCH":
		return http.MethodPatch, nil
	case "GET":
		return http.MethodGet, nil
	case "POST":
		return http.MethodPost, nil
	// Currently unsupported methods due to lack of support in http.Method.
	case "CONNECT":
		return http.MethodUnknown, nil
	case "TRACE":
		return http.MethodUnknown, nil
	default:
		return 0, fmt.Errorf("unsupported HTTP method: %s", method)
	}
}

func (tx *ebpfTXWrapper) resolveMethod() bool {
	if tx.method.malformed {
		return false
	}
	if tx.method.value != http.MethodUnknown {
		return true
	}

	if tx.Stream.Request_method.Index <= http2staticTableMaxEntry {
		switch uint8(tx.Stream.Request_method.Index) {
		case GetValue:
			tx.method.value = http.MethodGet
		case PostValue:
			tx.method.value = http.MethodPost
		default:
			tx.method.malformed = true
		}
		return !tx.method.malformed
	}

	tup := tx.Tuple
	// TODO: Support flipped tuples.

	stringMethod, exists := tx.dynamicTable.resolveValue(tup, tx.Stream.Request_method.Index, tx.Stream.Request_method.Temporary)
	if !exists {
		return false
	}
	method, err := stringToHTTPMethod(stringMethod)
	if err != nil {
		tx.method.malformed = true
		return false
	}
	tx.method.value = method
	return true
}

// Method returns the HTTP method of the transaction.
func (tx *ebpfTXWrapper) Method() http.Method {
	if tx.resolveMethod() {
		return tx.method.value
	}
	return http.MethodUnknown
}

// StatusCode returns the status code of the transaction.
// If the status code is indexed, then we return the corresponding value.
// Otherwise, f the status code is huffman encoded, then we decode it and convert it from string to int.
// Otherwise, we convert the status code from byte array to int.
func (tx *ebpfTXWrapper) StatusCode() uint16 {
	if tx.Stream.Status_code.Static_table_entry != 0 {
		switch tx.Stream.Status_code.Static_table_entry {
		case K200Value:
			return 200
		case K204Value:
			return 204
		case K206Value:
			return 206
		case K400Value:
			return 400
		case K500Value:
			return 500
		default:
			return 0
		}
	}

	if tx.Stream.Status_code.Is_huffman_encoded {
		// The final form of the status code is 3 characters.
		statusCode, err := hpack.HuffmanDecodeToString(tx.Stream.Status_code.Raw_buffer[:http2RawStatusCodeMaxLength-1])
		if err != nil {
			return 0
		}
		code, err := strconv.Atoi(statusCode)
		if err != nil {
			return 0
		}
		return uint16(code)
	}

	code, err := strconv.Atoi(string(tx.Stream.Status_code.Raw_buffer[:]))
	if err != nil {
		return 0
	}
	return uint16(code)
}

// SetStatusCode sets the HTTP status code of the transaction.
func (tx *ebpfTXWrapper) SetStatusCode(code uint16) {
	val := strconv.Itoa(int(code))
	if len(val) > http2RawStatusCodeMaxLength {
		return
	}
	copy(tx.Stream.Status_code.Raw_buffer[:], val)
}

// ResponseLastSeen returns the last seen response.
func (tx *ebpfTXWrapper) ResponseLastSeen() uint64 {
	return tx.Stream.Response_last_seen
}

// SetResponseLastSeen sets the last seen response.
func (tx *ebpfTXWrapper) SetResponseLastSeen(lastSeen uint64) {
	tx.Stream.Response_last_seen = lastSeen

}

// RequestStarted returns the timestamp of the request start.
func (tx *ebpfTXWrapper) RequestStarted() uint64 {
	return tx.Stream.Request_started
}

// SetRequestMethod sets the HTTP method of the transaction.
func (tx *ebpfTXWrapper) SetRequestMethod(method http.Method) {
	tx.method.value = method
}

// StaticTags returns the static tags of the transaction.
func (tx *ebpfTXWrapper) StaticTags() uint64 {
	return 0
}

// DynamicTags returns the dynamic tags of the transaction.
func (tx *ebpfTXWrapper) DynamicTags() []string {
	return nil
}

// String returns a string representation of the transaction.
func (tx *ebpfTXWrapper) String() string {
	var output strings.Builder
	output.WriteString("http2.ebpfTx{")
	output.WriteString(fmt.Sprintf("[%s] [%s ⇄ %s] ", tx.family(), tx.sourceEndpoint(), tx.destEndpoint()))
	output.WriteString(" Method: '" + tx.Method().String() + "', ")
	if tx.resolvePath() {
		output.WriteString("Path: '" + tx.path.value + "'")
	}
	output.WriteString("}")
	return output.String()
}

func (tx *ebpfTXWrapper) family() ebpf.ConnFamily {
	if tx.Tuple.Metadata&uint32(ebpf.IPv6) != 0 {
		return ebpf.IPv6
	}
	return ebpf.IPv4
}

func (tx *ebpfTXWrapper) sourceAddress() util.Address {
	if tx.family() == ebpf.IPv4 {
		return util.V4Address(uint32(tx.Tuple.Saddr_l))
	}
	return util.V6Address(tx.Tuple.Saddr_l, tx.Tuple.Saddr_h)
}

func (tx *ebpfTXWrapper) sourceEndpoint() string {
	return net.JoinHostPort(tx.sourceAddress().String(), strconv.Itoa(int(tx.Tuple.Sport)))
}

func (tx *ebpfTXWrapper) destAddress() util.Address {
	if tx.family() == ebpf.IPv4 {
		return util.V4Address(uint32(tx.Tuple.Daddr_l))
	}
	return util.V6Address(tx.Tuple.Daddr_l, tx.Tuple.Daddr_h)
}

func (tx *ebpfTXWrapper) destEndpoint() string {
	return net.JoinHostPort(tx.destAddress().String(), strconv.Itoa(int(tx.Tuple.Dport)))
}

func (t http2StreamKey) family() ebpf.ConnFamily {
	if t.Tup.Metadata&uint32(ebpf.IPv6) != 0 {
		return ebpf.IPv6
	}
	return ebpf.IPv4
}

func (t http2StreamKey) sourceAddress() util.Address {
	if t.family() == ebpf.IPv4 {
		return util.V4Address(uint32(t.Tup.Saddr_l))
	}
	return util.V6Address(t.Tup.Saddr_l, t.Tup.Saddr_h)
}

func (t http2StreamKey) sourceEndpoint() string {
	return net.JoinHostPort(t.sourceAddress().String(), strconv.Itoa(int(t.Tup.Sport)))
}

func (t http2StreamKey) destAddress() util.Address {
	if t.family() == ebpf.IPv4 {
		return util.V4Address(uint32(t.Tup.Daddr_l))
	}
	return util.V6Address(t.Tup.Daddr_l, t.Tup.Daddr_h)
}

func (t http2StreamKey) destEndpoint() string {
	return net.JoinHostPort(t.destAddress().String(), strconv.Itoa(int(t.Tup.Dport)))
}

// String returns a string representation of the http2 stream key.
func (t http2StreamKey) String() string {
	return fmt.Sprintf(
		"[%s] [%s ⇄ %s] (stream id %d)",
		t.family(),
		t.sourceEndpoint(),
		t.destEndpoint(),
		t.Id,
	)
}

// String returns a string representation of the http2 dynamic table.
func (t HTTP2DynamicTableEntry) String() string {
	if t.String_len == 0 {
		return ""
	}

	b := make([]byte, t.String_len)
	for i := uint8(0); i < t.String_len; i++ {
		b[i] = byte(t.Buffer[i])
	}
	// trim null byte + after
	str, err := hpack.HuffmanDecodeToString(b)
	if err != nil {
		return fmt.Sprintf("FAILED: %s", err)
	}

	return str
}

// String returns a string representation of the http2 eBPF telemetry.
func (t *HTTP2Telemetry) String() string {
	return fmt.Sprintf(`
HTTP2Telemetry{
	"requests seen": %d,
	"responses seen": %d,
	"end of stream seen": %d,
	"reset frames seen": %d,
	"literal values exceed message count": %d,
	"messages with more frames than we can filter": %d,
	"messages with more interesting frames than we can process": %d,
	"fragmented frame count": %d,
	"path headers length distribution": {
		"in range [0, 120)": %d,
		"in range [120, 130)": %d,
		"in range [130, 140)": %d,
		"in range [140, 150)": %d,
		"in range [150, 160)": %d,
		"in range [160, 170)": %d,
		"in range [170, 180)": %d,
		"in range [180, infinity)": %d
	}
}`, t.Request_seen, t.Response_seen, t.End_of_stream, t.End_of_stream_rst, t.Literal_value_exceeds_frame,
		t.Exceeding_max_frames_to_filter, t.Exceeding_max_interesting_frames, t.Fragmented_frame_count, t.Path_size_bucket[0], t.Path_size_bucket[1],
		t.Path_size_bucket[2], t.Path_size_bucket[3], t.Path_size_bucket[4], t.Path_size_bucket[5], t.Path_size_bucket[6],
		t.Path_size_bucket[7])
}
