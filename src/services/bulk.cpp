#include <hyle/services/bulk.h>

#include <algorithm>
#include <iterator>

namespace hyle::services {

void BulkTransfer::enqueue(const PubKey& dest, BulkKind kind, wire::View whole) {
  for (auto& q : out_)
    if (q.offset == 0 && q.kind == kind && q.dest == dest) {
      q.whole.assign(whole.begin(), whole.end());
      return;
    }
  Out o;
  o.dest = dest;
  o.kind = kind;
  o.whole.assign(whole.begin(), whole.end());
  o.id = next_id_++;
  o.offset = 0;
  out_.push_back(std::move(o));
}

size_t BulkTransfer::pump(size_t max_pieces, size_t piece_bytes,
                          const std::function<void(const PubKey&, wire::View)>& emit) {
  if (piece_bytes == 0) piece_bytes = 1;
  size_t sent = 0;
  while (sent < max_pieces && !out_.empty()) {
    Out& o = out_.front();
    const uint64_t remaining = o.whole.size() - o.offset;
    const uint32_t len = static_cast<uint32_t>(std::min<uint64_t>(remaining, piece_bytes));
    wire::Bytes piece;
    wire::Writer w(piece);
    w.u64(o.id);
    w.u8(static_cast<uint8_t>(o.kind));
    w.u64(o.whole.size());
    w.u64(o.offset);
    w.u32(len);
    w.raw(wire::View(o.whole.data() + o.offset, len));
    emit(o.dest, wire::View(piece.data(), piece.size()));
    o.offset += len;
    ++sent;
    // An empty artifact still sends one (len 0) piece so the receiver completes it.
    if (o.offset >= o.whole.size()) out_.pop_front();
  }
  return sent;
}

std::optional<BulkTransfer::Completed> BulkTransfer::receive(const PubKey& src, wire::View piece) {
  uint64_t id, total, offset;
  uint8_t kind;
  uint32_t len;
  wire::View body;
  try {
    wire::Reader r(piece);
    id = r.u64();
    kind = r.u8();
    total = r.u64();
    offset = r.u64();
    len = r.u32();
    body = r.raw(len);
    if (!r.empty()) return std::nullopt;
  } catch (const wire::Error&) {
    return std::nullopt;
  }
  if (kind > static_cast<uint8_t>(BulkKind::Blocks)) return std::nullopt;
  if (total > max_inbound_) return std::nullopt;
  if (offset > total || len > total - offset) return std::nullopt;

  const std::pair<PubKey, uint64_t> key{src, id};
  auto it = in_.find(key);
  if (it == in_.end()) {
    const auto first = in_.lower_bound({src, 0});
    size_t open = 0;
    for (auto j = first; j != in_.end() && j->first.first == src; ++j) ++open;
    if (open >= kMaxInboundPerSource) {
      if (id < first->first.second) return std::nullopt;
      in_.erase(first);
    }
    In in;
    in.kind = static_cast<BulkKind>(kind);
    in.total = total;
    it = in_.emplace(key, std::move(in)).first;
  }
  In& in = it->second;
  if (in.total != total || in.kind != static_cast<BulkKind>(kind)) {
    in_.erase(it);  // pieces of one transfer must agree on total and kind; a mismatch is corruption
    return std::nullopt;
  }
  // Placed by its own offset, so pieces may land in any order (e.g. split across two QoS lanes).
  if (len) {
    const auto next = in.pieces.lower_bound(offset);
    if (next != in.pieces.end() && next->first == offset && next->second.size() == len)
      return std::nullopt;
    const bool overlap =
        (next != in.pieces.end() && next->first < offset + len) ||
        (next != in.pieces.begin() && std::prev(next)->first + std::prev(next)->second.size() > offset);
    if (overlap) {
      in_.erase(it);
      return std::nullopt;
    }
    in.pieces.emplace_hint(next, offset, wire::Bytes(body.begin(), body.end()));
    in.got += len;
  }
  if (in.got < in.total) return std::nullopt;

  Completed done;
  done.src = src;
  done.kind = in.kind;
  done.whole.reserve(in.total);
  for (const auto& p : in.pieces) done.whole.insert(done.whole.end(), p.second.begin(), p.second.end());
  in_.erase(it);
  return done;
}

} // namespace hyle::services
