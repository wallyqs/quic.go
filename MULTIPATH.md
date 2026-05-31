# Multipath QUIC (quic-go ↔ quic-go)

Goal: let a **single** QUIC connection send over **multiple network paths
simultaneously**, so aggregate throughput can exceed a single network flow's
limit (e.g. AWS's ~5 Gbps per-5-tuple cap).

**Scope decision:** this is intentionally **NOT** wire-compatible with
draft-ietf-quic-multipath. It is designed to work only between two quic-go
endpoints that both enable multipath. Codepoints are borrowed from the IETF
draft to avoid collisions, but the framing/semantics are simplified.

This is the *opposite* of "many connections": one connection, one handshake,
one set of keys, multiple paths underneath.

## Why this isn't in upstream quic-go

Upstream implements **connection migration** (RFC 9000 §9): multiple candidate
paths, but only one active at a time. `pathManager.SwitchToPath` retires all
other paths; `Path.Switch` "immediately stops sending on the old path". The
send path, congestion controller (`internal/ackhandler`), RTT estimator, and
packet number spaces all assume a single active path.

## Phased plan

- **Phase 1 — wire foundation (DONE).**
  - `initial_max_path_id` transport parameter (`internal/wire/transport_parameters.go`):
    presence enables multipath; value = max path ID. Field `TransportParameters.InitialMaxPathID *uint64`.
  - New frames (`internal/wire/`): `PATH_ABANDON`, `PATH_AVAILABLE`/`PATH_BACKUP`
    (`PathAbandonFrame`, `PathStatusFrame`), wired into `frame_type.go` and
    `frame_parser.go` behind a `supportsMultipath` flag.
  - Full encode/decode + parser + transport-parameter round-trip tests.
  - NOT yet wired into the connection (`NewFrameParser(..., false)` in `connection.go`).

- **Phase 2 — negotiation + path-scoped connection IDs.** Plumb `EnableMultipath`
  through `Config`, send/parse `initial_max_path_id`, associate connection IDs
  with path IDs in `conn_id_manager.go` / `conn_id_generator.go`.

- **Phase 3 — per-path packet number spaces.** Add an AppData PN space per path
  in `internal/ackhandler`; route ACKs per path.

- **Phase 4 — per-path congestion control + RTT.** The hard part: one
  `congestion.SendAlgorithm` + `RTTStats` per path in `sent_packet_handler.go`.

- **Phase 5 — packet scheduler + send loop.** Choose a path per packet in
  `connection.go`'s send loop; add a throughput-oriented scheduler (fill the
  fastest available path first).

- **Phase 6 — public API + validation.** Expose adding/activating paths; test
  aggregate throughput across two paths.

## AWS caveat

Beating the 5 Gbps cap requires each path to be a **distinct 5-tuple that hashes
to a different ENA queue**. Differing source ports usually suffice; verify with
real throughput tests, and note the destination instance has its own per-flow
and aggregate-instance limits.
