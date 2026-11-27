package sniffer

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/otelcol-canopen/receiver/receiver/canopenreceiver/internal/cantransport"
	"github.com/otelcol-canopen/receiver/receiver/canopenreceiver/internal/codec"
	"github.com/otelcol-canopen/receiver/receiver/canopenreceiver/internal/emit"
)

func TestSniffer_PDO(t *testing.T) {
	s := New(Config{
		InterfaceName: "can0",
		PDOs: map[uint32]PDODef{
			0x181: {
				Name:  "motor_tpdo1",
				CobID: 0x181,
				Fields: []Field{
					{
						Name:       "canopen.motor.speed",
						BitOffset:  0,
						Type:       codec.Int16,
						Scale:      0.1,
						EmitMetric: true,
						EmitLog:    true,
						Attributes: map[string]any{"axis": "x", "priority": 200},
					},
				},
			},
		},
	})
	metrics := emit.NewMetricsBuilder()
	logs := emit.NewLogsBuilder()

	// int16 le 1000 = 0x03E8 -> bytes E8 03
	s.HandleFrame(cantransport.Frame{ID: 0x181, Data: []byte{0xE8, 0x03}}, metrics, logs)

	require.False(t, metrics.Empty())
	md := metrics.Emit()
	require.Equal(t, 1, md.ResourceMetrics().Len())
	m := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0)
	assert.Equal(t, "canopen.motor.speed", m.Name())
	dp := m.Gauge().DataPoints().At(0)
	assert.InDelta(t, 100.0, dp.DoubleValue(), 0.001)
	assert.Equal(t, "x", dp.Attributes().AsRaw()["axis"])
	assert.Equal(t, int64(200), dp.Attributes().AsRaw()["priority"])

	ld := logs.Emit()
	lr := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	assert.Equal(t, "motor_tpdo1", lr.Attributes().AsRaw()["canopen.pdo.name"])
	assert.Equal(t, "x", lr.Attributes().AsRaw()["axis"])
	assert.Equal(t, int64(200), lr.Attributes().AsRaw()["priority"])
	assert.InDelta(t, 100.0, lr.Body().Double(), 0.001)
}

func TestSniffer_FrameVariableLengthFields(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind codec.DataType
		want string
	}{
		{"string", codec.VisibleString, "v1.2"},
		{"bytes", codec.Bytes, "76312E32"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			field := Field{Name: "version", BitOffset: 8, Type: tc.kind, EmitLog: true}
			s := New(Config{
				InterfaceName: "can0",
				PDOs:          map[uint32]PDODef{0x181: {Name: "version", CobID: 0x181, Fields: []Field{field}}},
				RawCobIDs:     map[uint32]struct{}{0x501: {}},
				RawMessages:   map[uint32][]RawMessageDef{0x501: {{Name: "version", Fields: []Field{field}}}},
			})
			for _, id := range []uint32{0x181, 0x501} {
				logs := emit.NewLogsBuilder()
				s.HandleFrame(cantransport.Frame{ID: id, Data: []byte{1, 'v', '1', '.', '2'}}, nil, logs)
				require.False(t, logs.Empty())
				records := logs.Emit().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
				require.Equal(t, 1, records.Len())
				assert.Equal(t, tc.want, records.At(0).Body().Str())
			}
		})
	}
}

func TestSniffer_Heartbeat_StateChangeLogging(t *testing.T) {
	s := New(Config{InterfaceName: "can0", HeartbeatEmitLog: true, HeartbeatEmitMetric: true})
	metrics := emit.NewMetricsBuilder()
	logs := emit.NewLogsBuilder()

	// node 1 -> operational (0x05)
	s.HandleFrame(cantransport.Frame{ID: 0x701, Data: []byte{0x05}}, metrics, logs)
	require.False(t, logs.Empty())
	ld := logs.Emit()
	assert.Equal(t, 1, ld.ResourceLogs().Len())

	metrics.Emit() // reset

	// repeat same state: metric updates again, but no new log (state unchanged)
	s.HandleFrame(cantransport.Frame{ID: 0x701, Data: []byte{0x05}}, metrics, logs)
	assert.True(t, logs.Empty())
	assert.False(t, metrics.Empty())
}

func TestSniffer_EMCY(t *testing.T) {
	s := New(Config{InterfaceName: "can0", EMCYEmitLog: true, EMCYEmitMetric: true})
	metrics := emit.NewMetricsBuilder()
	logs := emit.NewLogsBuilder()

	// node 2, error code 0x2310 (current), register 0x01
	s.HandleFrame(cantransport.Frame{ID: 0x082, Data: []byte{0x10, 0x23, 0x01, 0, 0, 0, 0, 0}}, metrics, logs)

	require.False(t, logs.Empty())
	require.False(t, metrics.Empty())
	ld := logs.Emit()
	lr := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	assert.Contains(t, lr.Body().Str(), "0x2310")
}

func TestSniffer_SDOAbortProducesNoEmission(t *testing.T) {
	// Aborts carry no data to decode, and there is no generic undecoded
	// fallback - only explicitly declared SDOObjects are ever emitted.
	s := New(Config{
		InterfaceName: "can0",
		SDOObjects: []SDOObjectDef{{
			NodeID: 1, Index: 0x2001, SubIndex: 0x00,
			Fields: []Field{{Name: "canopen.test.value", Type: codec.Uint8, EmitLog: true}},
		}},
	})
	metrics := emit.NewMetricsBuilder()
	logs := emit.NewLogsBuilder()

	// Client 0x601 asks node 1 to upload object 0x2001:00.
	s.HandleFrame(
		cantransport.Frame{ID: 0x601, Data: []byte{0x40, 0x01, 0x20, 0x00, 0, 0, 0, 0}},
		metrics,
		logs,
	)
	// Node 1 rejects the request with abort code 0x06020000.
	s.HandleFrame(
		cantransport.Frame{ID: 0x581, Data: []byte{0x80, 0x01, 0x20, 0x00, 0, 0, 0x02, 0x06}},
		metrics,
		logs,
	)

	assert.True(t, metrics.Empty())
	assert.True(t, logs.Empty())
}

func TestSniffer_SDOChannelsSameNode(t *testing.T) {
	s := New(Config{
		InterfaceName: "can0",
		SDOChannels: []SDOChannel{
			{NodeID: 1, ClientToServerCobID: 0x601, ServerToClientCobID: 0x581},
			{NodeID: 1, ClientToServerCobID: 0x611, ServerToClientCobID: 0x591},
		},
		SDOObjects: []SDOObjectDef{{
			NodeID: 1, Index: 0x2001, SubIndex: 0x00,
			Fields: []Field{{Name: "canopen.test.value", Type: codec.Uint8, EmitLog: true}},
		}},
	})
	logs := emit.NewLogsBuilder()

	s.HandleFrame(cantransport.Frame{ID: 0x601, Data: []byte{0x40, 0x01, 0x20, 0x00, 0, 0, 0, 0}}, nil, logs)
	s.HandleFrame(cantransport.Frame{ID: 0x611, Data: []byte{0x40, 0x01, 0x20, 0x00, 0, 0, 0, 0}}, nil, logs)
	s.HandleFrame(cantransport.Frame{ID: 0x581, Data: []byte{0x43, 0x01, 0x20, 0x00, 1, 0, 0, 0}}, nil, logs)
	s.HandleFrame(cantransport.Frame{ID: 0x591, Data: []byte{0x43, 0x01, 0x20, 0x00, 2, 0, 0, 0}}, nil, logs)

	records := logs.Emit().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	require.Equal(t, 2, records.Len())
}

func TestSniffer_SDOUsesDefaultChannelsWhenUnconfigured(t *testing.T) {
	s := New(Config{
		InterfaceName: "can0",
		SDOObjects: []SDOObjectDef{{
			NodeID: 1, Index: 0x2001, SubIndex: 0x00,
			Fields: []Field{{Name: "canopen.test.value", Type: codec.Uint8, EmitLog: true}},
		}},
	})
	logs := emit.NewLogsBuilder()
	s.HandleFrame(cantransport.Frame{ID: 0x601, Data: []byte{0x2F, 0x01, 0x20, 0x00, 1, 0, 0, 0}}, nil, logs)
	require.Equal(t, 1, logs.Emit().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().Len())
}

func TestSniffer_TypedSDOObject(t *testing.T) {
	s := New(Config{
		InterfaceName: "can0",
		SDOObjects: []SDOObjectDef{{
			NodeID: 1, Index: 0x20F0, SubIndex: 0x11,
			Fields: []Field{{
				Name: "canopen.mcu.firmware", Type: codec.Uint32, EmitMetric: true, EmitLog: true,
				Attributes: map[string]any{"priority": 100},
			}},
		}},
	})
	metrics := emit.NewMetricsBuilder()
	logs := emit.NewLogsBuilder()

	s.HandleFrame(cantransport.Frame{ID: 0x601, Data: []byte{0x40, 0xF0, 0x20, 0x11, 0, 0, 0, 0}}, metrics, logs)
	s.HandleFrame(cantransport.Frame{ID: 0x581, Data: []byte{0x43, 0xF0, 0x20, 0x11, 0x1E, 0xB9, 0x75, 0x00}}, metrics, logs)

	md := metrics.Emit()
	require.Equal(t, 1, md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().Len())
	metric := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0)
	assert.Equal(t, "canopen.mcu.firmware", metric.Name())
	assert.Equal(t, float64(7715102), metric.Gauge().DataPoints().At(0).DoubleValue())
	assert.Equal(t, int64(100), metric.Gauge().DataPoints().At(0).Attributes().AsRaw()["priority"])

	ld := logs.Emit()
	records := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	record := records.At(records.Len() - 1)
	assert.Equal(t, int64(100), record.Attributes().AsRaw()["priority"])
	assert.InDelta(t, float64(7715102), record.Body().Double(), 0.001)
}

// TestSniffer_TypedSDOObjectStruct verifies that declaring multiple Fields
// on one SDOObjectDef decodes a struct (several named values) from a single
// completed SDO transfer, each with its own BitOffset - e.g. an
// IMPACT_INFO-shaped record (X/Y/Z bytes + a 32-bit pin code) - and that all
// of them land in one combined, structured log record.
func TestSniffer_TypedSDOObjectStruct(t *testing.T) {
	s := New(Config{
		InterfaceName: "can0",
		SDOObjects: []SDOObjectDef{{
			NodeID: 1, Index: 0x2160, SubIndex: 0x01,
			Fields: []Field{
				{Name: "impact.x", BitOffset: 0, Type: codec.Uint8, EmitLog: true},
				{Name: "impact.y", BitOffset: 8, Type: codec.Uint8, EmitLog: true},
				{Name: "impact.z", BitOffset: 16, Type: codec.Uint8, EmitLog: true},
				{Name: "impact.pin_code", BitOffset: 24, Type: codec.Uint32, EmitMetric: true, EmitLog: true},
			},
		}},
	})
	metrics := emit.NewMetricsBuilder()
	logs := emit.NewLogsBuilder()

	// Expedited 4-byte upload only carries 4 payload bytes; use segmented
	// upload to carry all 7 bytes (x=1, y=2, z=3, pin_code=0x11223344).
	s.HandleFrame(cantransport.Frame{ID: 0x601, Data: []byte{0x40, 0x60, 0x21, 0x01, 0, 0, 0, 0}}, nil, logs)
	s.HandleFrame(cantransport.Frame{ID: 0x581, Data: []byte{0x41, 0x60, 0x21, 0x01, 7, 0, 0, 0}}, nil, logs)
	s.HandleFrame(cantransport.Frame{ID: 0x601, Data: []byte{0x60, 0, 0, 0, 0, 0, 0, 0}}, nil, logs)
	// t=0, n=0 (all 7 bytes valid), c=1 (last segment) -> command byte 0x01.
	s.HandleFrame(cantransport.Frame{ID: 0x581, Data: []byte{0x01, 1, 2, 3, 0x44, 0x33, 0x22, 0x11}}, metrics, logs)

	require.False(t, metrics.Empty())
	md := metrics.Emit()
	metric := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0)
	assert.Equal(t, "impact.pin_code", metric.Name())
	assert.Equal(t, float64(0x11223344), metric.Gauge().DataPoints().At(0).DoubleValue())

	require.False(t, logs.Empty())
	records := logs.Emit().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	require.Equal(t, 1, records.Len())
	body := records.At(0).Body().Map().AsRaw()
	assert.InDelta(t, 1.0, body["impact.x"].(float64), 0.001)
	assert.InDelta(t, 2.0, body["impact.y"].(float64), 0.001)
	assert.InDelta(t, 3.0, body["impact.z"].(float64), 0.001)
	assert.InDelta(t, float64(0x11223344), body["impact.pin_code"].(float64), 0.001)
}

func TestSniffer_DuplicateSDOObjectEmitsOnce(t *testing.T) {
	s := New(Config{
		InterfaceName: "can0",
		SDOObjects: []SDOObjectDef{
			{NodeID: 1, Index: 0x20F0, SubIndex: 0x11, Fields: []Field{{Name: "device.firmware", Type: codec.Uint32, EmitMetric: true}}},
			{NodeID: 1, Index: 0x20F0, SubIndex: 0x11, Fields: []Field{{Name: "device.firmware", Type: codec.Uint32, EmitMetric: true}}},
		},
	})
	metrics := emit.NewMetricsBuilder()
	s.HandleFrame(cantransport.Frame{ID: 0x601, Data: []byte{0x40, 0xF0, 0x20, 0x11, 0, 0, 0, 0}}, metrics, nil)
	s.HandleFrame(cantransport.Frame{ID: 0x581, Data: []byte{0x43, 0xF0, 0x20, 0x11, 0x1E, 0xB9, 0x75, 0x00}}, metrics, nil)

	metricList := metrics.Emit().ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	require.Equal(t, 1, metricList.Len())
	assert.Equal(t, "device.firmware", metricList.At(0).Name())
}

func TestSniffer_SDOReassemblesSegmentedUpload(t *testing.T) {
	s := New(Config{
		InterfaceName: "can0",
		SDOObjects: []SDOObjectDef{{
			NodeID: 1, Index: 0x2001, SubIndex: 0x00,
			Fields: []Field{{Name: "canopen.test.greeting", Type: codec.VisibleString, ByteLen: 11, EmitLog: true}},
		}},
	})
	logs := emit.NewLogsBuilder()

	// Upload object 0x2001:00 in two segments: "hello w" + "orld".
	s.HandleFrame(
		cantransport.Frame{ID: 0x601, Data: []byte{0x40, 0x01, 0x20, 0x00, 0, 0, 0, 0}},
		nil,
		logs,
	)
	s.HandleFrame(cantransport.Frame{ID: 0x581, Data: []byte{0x41, 0x01, 0x20, 0x00, 11, 0, 0, 0}}, nil, logs)
	s.HandleFrame(cantransport.Frame{ID: 0x601, Data: []byte{0x60, 0, 0, 0, 0, 0, 0, 0}}, nil, logs)
	s.HandleFrame(cantransport.Frame{ID: 0x581, Data: []byte{0x00, 'h', 'e', 'l', 'l', 'o', ' ', 'w'}}, nil, logs)
	s.HandleFrame(cantransport.Frame{ID: 0x601, Data: []byte{0x70, 0, 0, 0, 0, 0, 0, 0}}, nil, logs)
	s.HandleFrame(cantransport.Frame{ID: 0x581, Data: []byte{0x17, 'o', 'r', 'l', 'd', 0, 0, 0}}, nil, logs)

	require.False(t, logs.Empty())
	body := logs.Emit().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body()
	assert.Equal(t, "hello world", body.Str())
}

func TestSniffer_SDOVariableLengthFields(t *testing.T) {
	for _, tc := range []struct {
		name   string
		kind   codec.DataType
		frames [][]byte
		want   string
	}{
		{"expedited string", codec.VisibleString, [][]byte{{0x4B, 0x0A, 0x10, 0, 'v', '1', 0, 0}}, "v1"},
		{"segmented string", codec.VisibleString, [][]byte{
			{0x41, 0x0A, 0x10, 0, 11, 0, 0, 0},
			{0x00, 'h', 'e', 'l', 'l', 'o', ' ', 'w'},
			{0x17, 'o', 'r', 'l', 'd', 0, 0, 0},
		}, "hello world"},
		{"expedited bytes", codec.Bytes, [][]byte{{0x4B, 0x0A, 0x10, 0, 'v', '1', 0, 0}}, "7631"},
		{"segmented bytes", codec.Bytes, [][]byte{
			{0x41, 0x0A, 0x10, 0, 8, 0, 0, 0},
			{0x00, 1, 2, 3, 4, 5, 6, 7},
			{0x1D, 8, 0, 0, 0, 0, 0, 0},
		}, "0102030405060708"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := New(Config{
				InterfaceName: "can0",
				SDOObjects: []SDOObjectDef{{
					NodeID: 1, Index: 0x100A,
					Fields: []Field{{Name: "device.version", Type: tc.kind, EmitLog: true}},
				}},
			})
			logs := emit.NewLogsBuilder()
			s.HandleFrame(cantransport.Frame{ID: 0x601, Data: []byte{0x40, 0x0A, 0x10, 0, 0, 0, 0, 0}}, nil, logs)
			for _, frame := range tc.frames {
				s.HandleFrame(cantransport.Frame{ID: 0x581, Data: frame}, nil, logs)
			}
			require.False(t, logs.Empty())
			records := logs.Emit().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
			require.Equal(t, 1, records.Len())
			assert.Equal(t, tc.want, records.At(0).Body().Str())
		})
	}
}

func TestSniffer_SDOUintAuto(t *testing.T) {
	for _, tc := range []struct {
		name    string
		reply   []byte
		want    float64
		wantErr string
	}{
		{"8-bit", []byte{0x4F, 0x01, 0x20, 0x00, 0x34, 0, 0, 0}, 0x34, ""},
		{"16-bit", []byte{0x4B, 0x01, 0x20, 0x00, 0x34, 0x12, 0, 0}, 0x1234, ""},
		{"32-bit", []byte{0x43, 0x01, 0x20, 0x00, 1, 0, 0, 0}, 1, ""},
		{"unsupported width", []byte{0x47, 0x01, 0x20, 0x00, 1, 0, 0, 0}, 0, "failed to decode"},
		{"unknown size", []byte{0x42, 0x01, 0x20, 0x00, 1, 0, 0, 0}, 0, "unknown or inconsistent SDO size"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			core, observed := observer.New(zapcore.WarnLevel)
			s := New(Config{
				InterfaceName: "can0",
				Logger:        zap.New(core),
				SDOObjects: []SDOObjectDef{{
					NodeID: 1, Index: 0x2001,
					Fields: []Field{{Name: "device.value", Type: codec.UintAuto, EmitLog: true}},
				}},
			})
			logs := emit.NewLogsBuilder()
			s.HandleFrame(cantransport.Frame{ID: 0x601, Data: []byte{0x40, 0x01, 0x20, 0x00, 0, 0, 0, 0}}, nil, logs)
			s.HandleFrame(cantransport.Frame{ID: 0x581, Data: tc.reply}, nil, logs)
			if tc.wantErr != "" {
				assert.True(t, logs.Empty())
				require.Equal(t, 1, observed.Len())
				assert.Contains(t, observed.All()[0].Message, tc.wantErr)
				return
			}
			require.False(t, logs.Empty())
			records := logs.Emit().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
			require.Equal(t, 1, records.Len())
			assert.Equal(t, tc.want, records.At(0).Body().Double())
			assert.Equal(t, 0, observed.Len())
		})
	}
}

func TestSniffer_SDOUintAutoRejectsSegmentedSizeMismatch(t *testing.T) {
	core, observed := observer.New(zapcore.WarnLevel)
	s := New(Config{
		InterfaceName: "can0",
		Logger:        zap.New(core),
		SDOObjects: []SDOObjectDef{{
			NodeID: 1, Index: 0x2001,
			Fields: []Field{{Name: "device.value", Type: codec.UintAuto, EmitLog: true}},
		}},
	})
	logs := emit.NewLogsBuilder()
	s.HandleFrame(cantransport.Frame{ID: 0x601, Data: []byte{0x40, 0x01, 0x20, 0x00, 0, 0, 0, 0}}, nil, logs)
	s.HandleFrame(cantransport.Frame{ID: 0x581, Data: []byte{0x41, 0x01, 0x20, 0x00, 1, 0, 0, 0}}, nil, logs)
	s.HandleFrame(cantransport.Frame{ID: 0x581, Data: []byte{0x0B, 0x34, 0x12, 0, 0, 0, 0, 0}}, nil, logs)
	assert.True(t, logs.Empty())
	require.Equal(t, 1, observed.Len())
	assert.Contains(t, observed.All()[0].Message, "unknown or inconsistent SDO size")
}

func TestSniffer_UnknownCobID_Ignored(t *testing.T) {
	s := New(Config{InterfaceName: "can0"})
	metrics := emit.NewMetricsBuilder()
	logs := emit.NewLogsBuilder()
	s.HandleFrame(cantransport.Frame{ID: 0x999, Data: []byte{1, 2, 3}}, metrics, logs)
	assert.True(t, metrics.Empty())
	assert.True(t, logs.Empty())
}

func TestSniffer_RawCapture(t *testing.T) {
	s := New(Config{
		InterfaceName: "can0",
		RawEmitMetric: true,
		RawEmitLog:    true,
		RawCobIDs:     map[uint32]struct{}{0x50E: {}},
	})
	metrics := emit.NewMetricsBuilder()
	logs := emit.NewLogsBuilder()

	s.HandleFrame(cantransport.Frame{ID: 0x50E, Data: []byte{0x08, 0x80, 1, 2, 3, 4, 5, 6}}, metrics, logs)

	require.False(t, metrics.Empty())
	require.False(t, logs.Empty())
	md := metrics.Emit()
	metric := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0)
	assert.Equal(t, "canopen.raw.frames", metric.Name())

	ld := logs.Emit()
	records := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	require.Equal(t, 1, records.Len())
	assert.Equal(t, "0880010203040506", strings.ToLower(records.At(0).Attributes().AsRaw()["canopen.raw.data"].(string)))
}

func TestSniffer_RawCapture_UnmatchedCobIDNotCaptured(t *testing.T) {
	s := New(Config{
		InterfaceName: "can0",
		RawEmitMetric: true,
		RawEmitLog:    true,
		RawCobIDs:     map[uint32]struct{}{0x50E: {}},
	})
	metrics := emit.NewMetricsBuilder()
	logs := emit.NewLogsBuilder()

	s.HandleFrame(cantransport.Frame{ID: 0x999, Data: []byte{1, 2, 3}}, metrics, logs)

	assert.True(t, metrics.Empty())
	assert.True(t, logs.Empty())
}

// TestSniffer_RawMessage_DecodesDeclaredSignals verifies that a raw message
// definition with a command word
// echo at bytes 0-1, then a little-endian uint32 part number at bytes 2-5
// and a little-endian uint16 extension at bytes 6-7) decodes into named
// fields without any bespoke processor.
func TestSniffer_RawMessage_DecodesDeclaredSignals(t *testing.T) {
	s := New(Config{
		InterfaceName: "can0",
		RawEmitMetric: true,
		RawEmitLog:    true,
		RawCobIDs:     map[uint32]struct{}{0x50E: {}},
		RawMessages: map[uint32][]RawMessageDef{
			0x50E: {
				{
					Name:  "raw.read_part_no",
					Match: []RawMatch{{ByteOffset: 0, Value: 0x08}, {ByteOffset: 1, Value: 0x80}},
					Fields: []Field{
						{Name: "raw.fw_part_no", BitOffset: 16, Type: codec.Uint32, EmitMetric: true},
						{Name: "raw.fw_extension", BitOffset: 48, Type: codec.Uint16, EmitLog: true},
					},
				},
			},
		},
	})
	metrics := emit.NewMetricsBuilder()
	logs := emit.NewLogsBuilder()

	// part no = 7715102 (0x75B91E), extension = 3.
	s.HandleFrame(cantransport.Frame{ID: 0x50E, Data: []byte{0x08, 0x80, 0x1E, 0xB9, 0x75, 0x00, 0x03, 0x00}}, metrics, logs)

	require.False(t, metrics.Empty())
	require.False(t, logs.Empty())

	md := metrics.Emit()
	metric := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0)
	assert.Equal(t, "raw.fw_part_no", metric.Name())
	assert.Equal(t, float64(7715102), metric.Gauge().DataPoints().At(0).DoubleValue())

	ld := logs.Emit()
	records := ld.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	require.Equal(t, 1, records.Len())
	assert.Equal(t, "raw.read_part_no", records.At(0).Attributes().AsRaw()["canopen.raw.message"])
	assert.InDelta(t, 3.0, records.At(0).Body().Double(), 0.001)
}

// TestSniffer_RawMessage_NoMatchFallsBackToRawHex verifies that when a
// frame's CobID has declared messages but none of their Match conditions
// are satisfied, the frame still falls back to raw hex capture rather than
// being dropped.
func TestSniffer_RawMessage_NoMatchFallsBackToRawHex(t *testing.T) {
	s := New(Config{
		InterfaceName: "can0",
		RawEmitMetric: true,
		RawEmitLog:    true,
		RawCobIDs:     map[uint32]struct{}{0x50E: {}},
		RawMessages: map[uint32][]RawMessageDef{
			0x50E: {
				{
					Name:   "raw.read_part_no",
					Match:  []RawMatch{{ByteOffset: 0, Value: 0x08}, {ByteOffset: 1, Value: 0x80}},
					Fields: []Field{{Name: "raw.fw_part_no", BitOffset: 16, Type: codec.Uint32, EmitMetric: true}},
				},
			},
		},
	})
	metrics := emit.NewMetricsBuilder()
	logs := emit.NewLogsBuilder()

	// A different command word does not match the declared message.
	s.HandleFrame(cantransport.Frame{ID: 0x50E, Data: []byte{0x46, 0x80, 1, 0, 0, 0, 0, 0}}, metrics, logs)

	require.False(t, metrics.Empty())
	md := metrics.Emit()
	metric := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics().At(0)
	assert.Equal(t, "canopen.raw.frames", metric.Name())
}
