#include <hyle/services/kv/state.h>

#include <hyle/core/crypto.h>

#include <algorithm>

namespace hyle {

void State::apply(const Op& op) {
  switch (op.kind) {
    case OpKind::Put:
      kv_[op.key] = op.val;
      break;
    case OpKind::Del:
      kv_.erase(op.key);
      break;
  }
}

void State::apply(const std::vector<Op>& ops) {
  for (const Op& op : ops) apply(op);
}

const wire::Bytes* State::get(wire::View key) const {
  wire::Bytes k(key.begin(), key.end());
  auto it = kv_.find(k);
  return it == kv_.end() ? nullptr : &it->second;
}

wire::Bytes State::canonical() const {
  std::vector<const wire::Bytes*> keys;
  keys.reserve(kv_.size());
  for (const auto& e : kv_) keys.push_back(&e.first);
  std::sort(keys.begin(), keys.end(),
            [](const wire::Bytes* a, const wire::Bytes* b) { return *a < *b; });

  wire::Bytes out;
  wire::Writer w(out);
  w.count(keys.size());
  for (const wire::Bytes* k : keys) {
    w.bytes(*k);
    w.bytes(kv_.at(*k));
  }
  return out;
}

void State::restore(wire::View canonical) {
  // Atomic: swap only on full success; a malformed snapshot leaves state unchanged.
  decltype(kv_) next;
  wire::Reader r(canonical);
  size_t n = r.count();
  next.reserve(n);
  wire::Bytes prev;
  bool have_prev = false;
  for (size_t i = 0; i < n; ++i) {
    wire::View k = r.bytes();
    wire::View v = r.bytes();
    wire::Bytes key(k.begin(), k.end());
    if (have_prev && !(prev < key)) throw wire::Error("state: keys not strictly ascending");
    prev = key;
    have_prev = true;
    next.emplace(std::move(key), wire::Bytes(v.begin(), v.end()));
  }
  if (!r.empty()) throw wire::Error("state: trailing bytes after entries");
  kv_ = std::move(next);
}

Hash State::app_hash() const { return sha256(canonical()); }

} // namespace hyle
