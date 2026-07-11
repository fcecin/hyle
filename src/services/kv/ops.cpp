#include <hyle/services/kv/ops.h>

#include <stdexcept>

namespace hyle::services::kv {

wire::Bytes encode_ops(const std::vector<Op>& ops) {
  wire::Bytes out;
  wire::Writer w(out);
  w.count(ops.size());
  for (const Op& op : ops) {
    w.u8(static_cast<uint8_t>(op.kind));
    w.bytes(op.key);
    if (op.kind == OpKind::Put) w.bytes(op.val);
  }
  return out;
}

std::vector<Op> decode_ops(wire::View in) {
  wire::Reader r(in);
  size_t n = r.count();
  std::vector<Op> ops;
  for (size_t i = 0; i < n; ++i) {
    uint8_t k = r.u8();
    Op op;
    wire::View key = r.bytes();
    op.key.assign(key.begin(), key.end());
    switch (static_cast<OpKind>(k)) {
      case OpKind::Put: {
        op.kind = OpKind::Put;
        wire::View val = r.bytes();
        op.val.assign(val.begin(), val.end());
        break;
      }
      case OpKind::Del:
        op.kind = OpKind::Del;
        break;
      default:
        throw wire::Error("ops: unknown op kind");
    }
    ops.push_back(std::move(op));
  }
  if (!r.empty()) throw wire::Error("ops: trailing bytes");
  return ops;
}

} // namespace hyle::services::kv
