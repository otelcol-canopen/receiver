# CANopen OpenTelemetry Collector

An OpenTelemetry Collector receiver and distribution for CANopen over Linux
SocketCAN. It collects telemetry from passive bus traffic and can actively
read configured CANopen objects over SDO.

## Capabilities

- Decode configured PDO fields into metrics and logs.
- Observe heartbeat/NMT state changes and EMCY messages.
- Observe standard SDO uploads and downloads, including segmented transfers,
  and decode configured objects.
- Actively upload configured SDO objects once or on an interval, with optional
  retry and backoff settings.
- Capture raw CAN frames or decode configured vendor-specific messages and
  request/response transactions.
- Use one or more CANopen receivers in normal Collector pipelines with other
  receivers, processors, exporters, and extensions.

All decoding and emission is controlled by receiver configuration. See the
[receiver documentation](./receiver/canopenreceiver/README.md) for the
configuration reference and emitted telemetry details.

## Build and run

Build the `otelcol-canopen` Collector distribution with the
[OpenTelemetry Collector Builder](https://github.com/open-telemetry/opentelemetry-collector/tree/main/cmd/builder):

```sh
make build-device
./dist/otelcol-canopen --config=config/example-collector.yaml
```

The distribution includes the CANopen and OTLP receivers, OTLP and debug
exporters, `batch` and `memory_limiter` processors, a transform processor,
and the `zpages` extension. The example config listens for OTLP on ports
`4317` (gRPC) and `4318` (HTTP), and for CANopen traffic on `vcan0`. It sends
telemetry to the debug exporter and to an upstream OTLP endpoint, configurable
with `OTLP_EXPORTER_ENDPOINT` (default: `localhost:4317`).

The provided [dev container](./.devcontainer) creates `vcan0` for testing
without hardware. In a second terminal, run `make run-publisher` to publish
sample heartbeat, TPDO, and optional EMCY frames for the example config.

## Repository contents

- [`builder-config.yaml`](./builder-config.yaml) defines the `otelcol-canopen`
  distribution and its components.
- [`receiver/canopenreceiver`](./receiver/canopenreceiver) contains the
  receiver module.
- [`config/example-collector.yaml`](./config/example-collector.yaml) provides
  an example metrics and logs pipeline.
- [`cmd/canopen-publisher`](./cmd/canopen-publisher) publishes sample CANopen
  traffic for development and testing.
- [`.github/workflows/ci.yaml`](./.github/workflows/ci.yaml) builds and tests
  the receiver and distribution.
