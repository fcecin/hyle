#ifndef HYLE_MORPHE_SCHEMA_H
#define HYLE_MORPHE_SCHEMA_H

#include <hyle/core/crypto.h>
#include <hyle/core/wire.h>

#include <cstdint>
#include <cstring>

namespace hyle::morphe {

inline constexpr uint8_t ACCOUNT_PREFIX = 'a';
inline constexpr uint8_t ENTRY_PREFIX = 'e';

inline wire::Bytes account_key(const PubKey& pk) {
  wire::Bytes k;
  k.reserve(1 + pk.size());
  k.push_back(ACCOUNT_PREFIX);
  k.insert(k.end(), pk.begin(), pk.end());
  return k;
}

// The sequence is the replay guard for every op this key signs.
struct Account {
  uint64_t balance = 0;
  uint64_t sequence = 0;

  wire::Bytes encode() const {
    wire::Bytes out;
    wire::Writer w(out);
    w.u64(balance);
    w.u64(sequence);
    return out;
  }
  static Account decode(wire::View v) {
    wire::Reader r(v);
    Account a;
    a.balance = r.u64();
    a.sequence = r.u64();
    if (!r.empty()) throw wire::Error("morphe: account value has trailing bytes");
    return a;
  }
};

inline wire::Bytes entry_key(wire::View name) {
  wire::Bytes k;
  k.reserve(1 + name.size());
  k.push_back(ENTRY_PREFIX);
  k.insert(k.end(), name.begin(), name.end());
  return k;
}

struct Entry {
  PubKey owner{};
  uint64_t balance = 0;
  uint64_t created = 0;
  uint64_t last_modified = 0;
  uint64_t last_rent = 0;
  wire::Bytes payload;

  static constexpr uint64_t HEADER = 32 + 8 + 8 + 8 + 8;

  wire::Bytes encode() const {
    wire::Bytes out;
    wire::Writer w(out);
    w.raw(wire::View(owner.data(), owner.size()));
    w.u64(balance);
    w.u64(created);
    w.u64(last_modified);
    w.u64(last_rent);
    if (!payload.empty()) w.raw(wire::View(payload.data(), payload.size()));
    return out;
  }
  static Entry decode(wire::View v) {
    wire::Reader r(v);
    Entry e;
    std::memcpy(e.owner.data(), r.raw(32).data(), 32);
    e.balance = r.u64();
    e.created = r.u64();
    e.last_modified = r.u64();
    e.last_rent = r.u64();
    size_t rem = r.remaining();
    if (rem > 0) {
      wire::View p = r.raw(rem);
      e.payload.assign(p.begin(), p.end());
    }
    return e;
  }
};

} // namespace hyle::morphe

#endif
