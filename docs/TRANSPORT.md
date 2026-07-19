# The Transport seam

The Hyle base is IO-free: it emits outbound bytes and consumes inbound bytes, and no sockets appear in it. A transport moves those bytes between nodes. A `hyle::Node` never calls the engine; the transport drives the engine with what the node produces and hands back what peers send. Layer 1 is proven against an in-process mock transport.

## Message classes

- Consensus messages (opaque). The engine emits them through `Application::publish`; the node collects them (`drain_outbox`). The transport broadcasts each to the other validators and feeds every received one to `Engine::recv`. Content is malachite's own codec; the transport does not inspect it.
- Proposed values. Hyle runs the parts payload mode, so the value does not ride the opaque proposal and the transport must disseminate it. When a node proposes (`wants_propose` / `proposal_value`), the transport delivers the value bytes to each peer, which calls `Node::accept_proposed(value)` and then `Engine::proposed_value(height, round, nil, proposer, value, valid, Consensus)`.
- Timeouts. The engine requests timers via `Application::schedule_timeout`; the transport fires them via `Engine::timeout_elapsed` when due.
- Catch-up. A behind node broadcasts a small SnapReq (CheckpointReq); peers reply with their checkpoint (SnapResp), which the joiner pools per content until a >2/3 attestation quorum forms. It then sends BlobReq for that height's state blob and for the trailing blocks; the peer streams each as a WHOLE artifact over `hyle::services::BulkTransfer`, which splits it into `max_message`-sized BulkChunk pieces and reassembles it on arrival. The core deals only in whole snapshots and whole blocks: it verifies the state blob against the quorum-checked AppHash (`Node::adopt_state_blob`) and each block against its certificate. `hyle::services::Runtime` drives both ends; the chunker is reusable and transport-agnostic.

## Delivery semantics

- Consensus and value dissemination tolerate loss, reordering, and duplication; best-effort datagrams are acceptable.
- Dedup may gate forwarding and re-flooding, never local delivery of Consensus/Prop frames: the engine's liveness rebroadcasts are byte-identical, and a peer whose engine lost its first copy (rebuilt by catch-up) can only recover a round's votes from a re-delivery. The engine dedups votes itself.
- Bulk transfer (BulkChunk pieces) needs reliable, ordered delivery per message: TCP and the CES RUDP stream both provide it, so the chunker does split/reassemble only, never retransmit or reorder. It rides the same transport as consensus, tagged `Channel::Bulk`; a transport may route that channel onto a separate stream so a long transfer never head-of-line-blocks consensus, but the chunker also paces pieces so it interleaves on a shared one.
- A validator the transport cannot reach is absent; consensus continues while a quorum (more than 2/3 of voting power) is reachable. An absent validator rejoins by snapshot, not replay.

## What a transport must provide

1. Broadcast a node's outbound consensus messages and deliver received ones to `Engine::recv`.
2. Disseminate a proposer's value, invoking `accept_proposed` + `Engine::proposed_value`.
3. Fire scheduled timeouts via `Engine::timeout_elapsed`.
4. Carry the small sync-control messages (SnapReq/SnapResp/ValueReq) and the BulkChunk pieces between peers, reliably and in order per message. Set `max_message` to the largest payload one send carries (the chunker sizes pieces to it); the serving/fetching/splitting/reassembly is `Runtime` + `BulkTransfer`, not the transport.

It need not provide identity or signing (the node owns ed25519), transaction ordering (consensus does), chunking or reassembly (`BulkTransfer` does), or any understanding of value, governance, or state bytes.

## Reference

`tests/local_cluster.h` is the reference in-process transport: a synchronous broadcast implementing all four responsibilities over direct calls, with offline nodes and snapshot join.
