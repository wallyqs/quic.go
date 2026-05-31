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

- **Phase 2a — negotiation (DONE).**
  - `Config.EnableMultipath` (`interface.go`), propagated in `config.go`.
  - Both transport-parameter builders in `connection.go` send `initial_max_path_id`
    (= `protocol.MultipathMaxPathID`) when enabled.
  - `NewFrameParser` now receives `c.config.EnableMultipath`, so multipath frames
    are accepted once enabled locally.
  - `ConnectionState.SupportsMultipath{Local,Remote}` exposes negotiation; multipath
    is "active" only when both sides advertise it.
  - Integration test `TestHandshakeMultipathNegotiation` covers all four combinations.

- **Phase 2b — path-scoped connection IDs (DONE, pre-existing).**
  The connection ID manager already maps path IDs to distinct connection IDs
  via `connIDManager.GetConnIDForPath` / `RetireConnIDForPath` and the
  `pathProbing` map — built for connection migration, but it already keeps
  multiple paths' connection IDs (and stateless reset tokens) active
  simultaneously, which is exactly what multipath needs. Locked in by
  `TestConnIDManagerMultipathSimultaneousPaths`. No new code required here.

- **Phase 3 — per-path packet number spaces (IN PROGRESS).**
  - Added `ackhandler.PathID` (`internal/ackhandler/path.go`); the initial path is `InitialPathID` (0).
  - `sentPacketHandler` now holds `appDataPaths map[PathID]*packetNumberSpace`,
    with path 0 aliasing the existing `appDataPackets`. Added `addPath`,
    `appDataPath` and `removePath`, and kept the path-0 entry in sync across
    `ResetForRetry`.
  - White-box test `TestSentPacketHandlerPerPathPacketNumberSpaces` verifies
    independent per-path packet numbering. Existing single-path suite still
    passes (no path-0 regression).
  - REMAINING: route received ACKs to the right path's space, and per-path
    loss detection (currently loss/PTO still read path 0). This merges into
    Phase 4, since `packetNumberSpace` carries `lossTime`/`lastAckElicitingPacketTime`.

- **Phase 4 — per-path congestion control + RTT (IN PROGRESS).**
  - `pathState` (`internal/ackhandler/path.go`) now bundles each path's packet
    number space, congestion controller, RTT estimator and bytes-in-flight.
  - The initial path reuses the handler's shared congestion controller and RTT
    estimator (so single-path behavior is byte-for-byte unchanged); additional
    paths get fresh, independent ones via `newPathState`.
  - `TestSentPacketHandlerPerPathPacketNumberSpaces` verifies that packet
    numbering and RTT estimation are independent across paths.
  - REMAINING: have `SentPacket` / `ReceivedAck` / `SendMode` consult the
    per-path congestion controller and RTT for non-zero paths. Today they still
    use the shared (path-0) controller, because nothing sends on additional
    paths until the scheduler exists (Phase 5). This is the integration point.

- **Phase 5 — packet scheduler + send loop (IN PROGRESS).**
  - `selectSendablePaths` (`path_scheduler.go`): throughput scheduling policy.
    Pure and fully unit-tested.
  - Path-aware packet number API landed: `PeekPacketNumberForPath` /
    `PopPacketNumberForPath` on the `SentPacketHandler` interface (mock
    regenerated), implemented against the per-path packet number space, with
    path-0 equivalence tested.
  - Per-path send + ACK accounting landed: `SentPacketForPath`,
    `SendModeForPath` and `ReceivedAckForPath` on the interface. For additional
    paths these record/ack against the path's own packet number space,
    congestion controller, RTT estimator and bytes-in-flight, including
    self-contained per-path loss detection (`sent_packet_handler_multipath.go`).
    The initial path delegates to the existing single-path methods, so its
    behavior is unchanged. White-box tested (send → ACK → bytes-in-flight drains,
    independent per-path RTT).
  - REMAINING (the big, unvalidatable-in-CI integration):
    1. `packetPacker`: a path-aware 1-RTT data-packing method (pack with a
       given path's connection ID + packet number, assigning stream/control
       frames to the path). Today only `PackPathProbePacket(connID, frames)`
       packs for a specific connection ID, and it uses the default path's PN.
    2. `connection.go` send loop: iterate `selectSendablePaths`, pack a packet
       per path via the packer, write it to that path's transport socket, and
       call `SentPacketForPath`.
    3. Receive side: demux incoming packets to their path and call
       `ReceivedAckForPath` (in our quic-go-only design, the path is identified
       by the local connection ID the packet arrived on).
    4. Public API (phase 6) to open + activate additional paths simultaneously
       (today `Path.Switch()` is an exclusive hand-off).
    This needs real multi-path network validation (AWS), so it is being wired
    slice by slice rather than as one blind rewrite of the send path.

- **Phase 6 — public API + validation.** Expose adding/activating paths; test
  aggregate throughput across two paths.

## AWS caveat

Beating the 5 Gbps cap requires each path to be a **distinct 5-tuple that hashes
to a different ENA queue**. Differing source ports usually suffice; verify with
real throughput tests, and note the destination instance has its own per-flow
and aggregate-instance limits.
