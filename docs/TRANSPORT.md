# The Transport seam

The Hyle base is IO-free: it emits outbound bytes and consumes inbound bytes, and no sockets appear in it. A transport moves those bytes between nodes. A `hyle::Node` never calls the engine; the transport drives the engine with what the node produces and hands back what peers send. Layer 1 is proven against an in-process mock transport.

## Message classes

- Consensus messages (opaque). The engine emits them through `Application::publish`; the node collects them (`drain_outbox`). The transport broadcasts each to the other validators and feeds every received one to `Engine::recv`. Content is malachite's own codec; the transport does not inspect it.
- Proposed values. Hyle runs the parts payload mode, so the value does not ride the opaque proposal and the transport must disseminate it. When a node proposes (`wants_propose` / `proposal_value`), the transport delivers the value bytes to each peer, which calls `Node::accept_proposed(value)` and then `Engine::proposed_value(height, round, nil, proposer, value, valid, Consensus)`.
- Timeouts. The engine requests timers via `Application::schedule_timeout`; the transport fires them via `Engine::timeout_elapsed` when due.
- Snapshots (far-behind / fresh join). A joiner broadcasts SnapReq; every peer serves its stored self-attested snapshot (SnapResp); the joiner pools attestations per content and adopts on `Node::adopt_snapshot`'s quorum. `hyle::services::Runtime` drives both ends.
- Block sync (behind catch-up). A behind node sends ValueReq; a peer serves its retained blocks with certificates (ValueResp), sized to `Transport::max_message`; the requester replays each via `Engine::sync_value_response` -> `Node::sync_value` -> `Engine::proposed_value(.., Sync)`; the engine verifies the certificate. `Runtime` drives both ends.

## Delivery semantics

- Consensus and value dissemination tolerate loss, reordering, and duplication; best-effort datagrams are acceptable.
- Dedup may gate forwarding and re-flooding, never local delivery of Consensus/Prop frames: the engine's liveness rebroadcasts are byte-identical, and a peer whose engine lost its first copy (rebuilt by catch-up) can only recover a round's votes from a re-delivery. The engine dedups votes itself.
- Snapshot transfer needs reliability and ordering; a reliable stream (TCP) is the natural carrier.
- A validator the transport cannot reach is absent; consensus continues while a quorum (more than 2/3 of voting power) is reachable. An absent validator rejoins by snapshot, not replay.

## What a transport must provide

1. Broadcast a node's outbound consensus messages and deliver received ones to `Engine::recv`.
2. Disseminate a proposer's value, invoking `accept_proposed` + `Engine::proposed_value`.
3. Fire scheduled timeouts via `Engine::timeout_elapsed`.
4. Carry the sync messages (ValueReq/ValueResp, SnapReq/SnapResp) between peers; `Runtime` implements serving and fetching. Override `max_message` when the transport caps a frame, so responses are sized to arrive.

It need not provide identity or signing (the node owns ed25519), transaction ordering (consensus does), or any understanding of value, governance, or state bytes.

## Reference

`tests/local_cluster.h` is the reference in-process transport: a synchronous broadcast implementing all four responsibilities over direct calls, with offline nodes and snapshot join.
