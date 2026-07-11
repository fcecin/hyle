#ifndef HYLE_SERVICES_SCHEMA_H
#define HYLE_SERVICES_SCHEMA_H

#include <hyle/core/crypto.h>
#include <hyle/core/wire.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

namespace hyle::services {

// The key prefix is the access control: account_key() and entry_key() are the only
// constructors a user op can reach, so a pending sudo proposal lives at 'g', which no user
// op builds.
inline constexpr uint8_t ACCOUNT_PREFIX = 'a';
inline constexpr uint8_t ENTRY_PREFIX = 'e';
inline constexpr uint8_t PENDING_PREFIX = 'g';

// The mint sentinel. A sudo transfer from this key mints: the source is never debited. No
// other source creates credit.
inline constexpr PubKey MINT_SENTINEL{};

inline bool is_mint_sentinel(const PubKey& k) { return k == MINT_SENTINEL; }

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
    if (!r.empty()) throw wire::Error("services: account value has trailing bytes");
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

// A pending sudo proposal: the act and the members that approved it, keyed by proposer so a
// member holds at most one (bounding the namespace to the validator set; the cell pays no
// rent). Overwritten by the proposer's next proposal, cleared when the proposer leaves the
// set, or dropped by an Approve once older than sudo_ttl. created exists only for the ttl.
inline wire::Bytes pending_key(const PubKey& proposer) {
  wire::Bytes k;
  k.reserve(1 + proposer.size());
  k.push_back(PENDING_PREFIX);
  k.insert(k.end(), proposer.begin(), proposer.end());
  return k;
}

struct Pending {
  uint64_t created = 0;
  std::vector<PubKey> voters;  // ascending, deduped; includes the proposer
  wire::Bytes inner;

  bool has_voted(const PubKey& k) const {
    return std::find(voters.begin(), voters.end(), k) != voters.end();
  }
  // Keep the set canonical: every node must encode the same bytes.
  void add_voter(const PubKey& k) {
    auto it = std::lower_bound(voters.begin(), voters.end(), k);
    if (it == voters.end() || !(*it == k)) voters.insert(it, k);
  }

  wire::Bytes encode() const {
    wire::Bytes out;
    wire::Writer w(out);
    w.u64(created);
    w.count(voters.size());
    for (const auto& v : voters) w.raw(wire::View(v.data(), v.size()));
    w.bytes(wire::View(inner.data(), inner.size()));
    return out;
  }
  static Pending decode(wire::View v) {
    wire::Reader r(v);
    Pending p;
    p.created = r.u64();
    const size_t n = r.count();
    for (size_t i = 0; i < n; ++i) {
      PubKey k{};
      std::memcpy(k.data(), r.raw(32).data(), 32);
      p.voters.push_back(k);
    }
    wire::View in = r.bytes();
    p.inner.assign(in.begin(), in.end());
    if (!r.empty()) throw wire::Error("services: pending has trailing bytes");
    return p;
  }
};

} // namespace hyle::services

#endif
