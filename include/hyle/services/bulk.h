#ifndef HYLE_SERVICES_BULK_H
#define HYLE_SERVICES_BULK_H

// The reusable bulk-transfer facility: it moves whole artifacts (a state blob, a block batch) over
// a transport that provides only a reliable, ordered, per-message send -- exactly what TCP and the
// CES RUDP stream both are. On send it splits the artifact into pieces the transport can carry and
// paces them so a long transfer interleaves with consensus; on receive it reassembles the pieces
// and hands back the whole artifact. It never retransmits or reorders -- the transport's stream
// already guarantees delivery. Single-source, offset-addressed; no cross-source chunk reuse.
//
// A transport implementer never touches this: it moves BulkChunk messages like any other, and (if
// it wants) routes Channel::Bulk onto a separate stream so bulk never head-of-line-blocks consensus.

#include <hyle/core/crypto.h>
#include <hyle/core/wire.h>

#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <utility>

namespace hyle::services {

enum class BulkKind : uint8_t { StateBlob = 0, Blocks = 1 };

class BulkTransfer {
public:
  // Piece wire form: [u64 id][u8 kind][u64 total][u64 offset][u32 len][len bytes].
  static constexpr size_t kPieceHeader = 8 + 1 + 8 + 8 + 4;

  // Queue a whole artifact to `dest`. `whole` is copied; the caller's buffer need not persist.
  void enqueue(const PubKey& dest, BulkKind kind, wire::View whole);
  bool sending() const { return !out_.empty(); }
  size_t outbound() const { return out_.size(); }
  size_t inbound() const { return in_.size(); }

  // Emit up to `max_pieces` pieces, each carrying <= `piece_bytes` of artifact, through `emit`.
  // Call it every pump so a transfer drains gradually and consensus messages slot between pieces.
  size_t pump(size_t max_pieces, size_t piece_bytes,
              const std::function<void(const PubKey& dest, wire::View piece)>& emit);

  struct Completed {
    PubKey src;
    BulkKind kind;
    wire::Bytes whole;
  };
  // Feed one received BulkChunk payload. Returns the whole artifact when its last piece lands.
  // Malformed input, an over-cap total, or an out-of-order piece drops the transfer and returns
  // nullopt.
  std::optional<Completed> receive(const PubKey& src, wire::View piece);

  // Reject any inbound transfer that declares more than this many bytes.
  void set_max_inbound(uint64_t bytes) { max_inbound_ = bytes; }

private:
  struct Out {
    PubKey dest;
    BulkKind kind;
    wire::Bytes whole;
    uint64_t id = 0;
    uint64_t offset = 0;
  };
  struct In {
    BulkKind kind = BulkKind::StateBlob;
    uint64_t total = 0;
    uint64_t got = 0;
    wire::Bytes buf;
  };

  std::deque<Out> out_;
  uint64_t next_id_ = 1;
  std::map<std::pair<PubKey, uint64_t>, In> in_;
  uint64_t max_inbound_ = 4ull << 30;  // 4 GiB
};

} // namespace hyle::services

#endif
