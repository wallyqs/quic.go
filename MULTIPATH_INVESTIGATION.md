# Why quic-go v0.54 has no true (simultaneous-path) multipath QUIC

_Investigation against quic-go `master` (module `github.com/quic-go/quic-go`, post-v0.54), 2026-05-31._

## TL;DR

quic-go implements **connection migration** (RFC 9000), **not** the **QUIC multipath
extension** ([draft-ietf-quic-multipath](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/)).

- Migration = multiple candidate paths, but **only one carries traffic at a time**.
- Multipath  = **multiple paths sending simultaneously**, with per-path congestion control.

Only multipath can push one logical connection past a single network flow's bandwidth
limit. quic-go deliberately doesn't implement it yet, for architectural reasons listed below.

## Evidence in the code

### 1. Switching to a path tears down all others

`path_manager.go` — `SwitchToPath` retires every path except the chosen one:

```go
// SwitchToPath is called when the connection switches to a new path
func (pm *pathManager) SwitchToPath(addr net.Addr) {
	// retire all other paths
	for _, path := range pm.paths {
		if addrsEqual(path.addr, addr) {
			continue
		}
		pm.retireConnID(path.id)   // all but the chosen path are retired
	}
	clear(pm.paths)
	pm.paths = pm.paths[:0]
}
```

### 2. The public API documents switching as exclusive

`path_manager_outgoing.go` — `Path.Switch()`:

```go
// Switch switches the QUIC connection to this path.
// It immediately stops sending on the old path, and sends on this new path.
func (p *Path) Switch() error { ... }
```

The exported surface (`Transport.AddPath` → `Path.Probe` → `Path.Switch` → `Path.Close`)
is a baton pass between paths, never a fan-out. Probe paths are capped at
`maxPaths = 3` (`path_manager.go`), and that cap is only for tracking probes, not
concurrent data paths.

### 3. Single congestion controller / RTT estimator per connection

`internal/ackhandler/sent_packet_handler.go` holds exactly one of each:

```go
congestion congestion.SendAlgorithmWithDebugInfos
rttStats   *utils.RTTStats
```

Simultaneous paths need **per-path** congestion control and RTT estimation, since each
path has independent bandwidth, loss, and latency.

### 4. None of the multipath wire format exists

Searching non-test `.go` files for `multipath`, `MaxPaths`, `initial_max_path`,
`PATH_ABANDON`, `MP_ACK`, etc. returns nothing. The extension requires:

- the `initial_max_path_id` transport parameter,
- new frames: `PATH_ABANDON`, `PATH_AVAILABLE`/`PATH_BACKUP`, `MP_ACK`, `MP_RETIRE_CONNECTION_ID`,
- a **separate packet number space per path ID**.

## Why it's hard (the real reason it isn't done)

True multipath breaks core single-path assumptions:

1. **Per-path congestion control & RTT** — biggest lift; touches the most
   correctness-sensitive code (loss recovery, pacing, flow control).
2. **Per-path packet number spaces** — new frames + transport parameter + ACK handling.
3. **A packet scheduler** — deciding which path each packet goes on, plus receiver-side
   reordering tolerance. No such component exists today.
4. **Spec timing** — the IETF draft only recently stabilized; maintainers are waiting
   for a settled spec and a well-tested design before retrofitting per-path state.

## Relevance to the AWS 5 Gbps ceiling

- AWS enforces a **per-flow (5-tuple) cap of ~5 Gbps** for traffic within a Region/across
  AZs (≈half that to the internet / cross-Region), via ENA flow hashing. Aggregate
  instance bandwidth is far higher — the limit is per flow.
- A normal QUIC connection is **one UDP 5-tuple**, so QUIC tuning alone can't beat it.
- **Caveat even with real multipath:** it only helps if each path is a *distinct 5-tuple
  that hashes to a different ENA queue*. Same src/dst IP differing only by source port may
  not land on a different physical lane, and AWS sometimes caps the *aggregate* between a
  single instance↔instance pair. So multipath is necessary but not automatically sufficient.

## Practical options (none require waiting on quic-go multipath)

1. **Parallel connections** — open N independent QUIC connections (distinct 5-tuples) and
   stripe data across them at the application layer. Works on stock quic-go today and
   sidesteps per-path congestion control. Most pragmatic path to >5 Gbps on AWS.
2. **Multipath research forks** — older mpquic forks exist but lag mainline quic-go and
   carry the same ENA-hashing caveat; evaluate maintainability carefully.
3. **Prototype real multipath** in this tree — large effort (per-path CC, packet number
   spaces, scheduler); design + estimate first.

## References

- draft-ietf-quic-multipath: https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/
- RFC 9000 §9 (Connection Migration): https://www.rfc-editor.org/rfc/rfc9000#section-9
- AWS EC2 network bandwidth (per-flow limits):
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-network-bandwidth.html
