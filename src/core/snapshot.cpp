#include <hyle/core/snapshot.h>

#include <cstring>
#include <set>

namespace hyle {

// Do not drop chain_id from the composite hash without re-checking cross-chain replay.
wire::Bytes attestation_bytes(uint64_t height, const Hash& app_hash) {
  wire::Bytes out;
  wire::Writer w(out);
  w.raw(wire::View(reinterpret_cast<const uint8_t*>("HYLE_APPHASH_V1"), 15));
  w.u64(height);
  w.raw(wire::View(app_hash.data(), app_hash.size()));
  return out;
}

namespace {

void put_vset(wire::Writer& w, const malachite::ValidatorSet& vs) {
  w.count(vs.size());
  for (const auto& v : vs) {
    if (v.public_key.size() != 32) throw wire::Error("snapshot: validator key must be 32 bytes");
    w.raw(wire::View(v.public_key.data(), 32));
    w.u64(v.voting_power);
  }
}

malachite::ValidatorSet get_vset(wire::Reader& r) {
  malachite::ValidatorSet vs;
  size_t n = r.count();
  for (size_t i = 0; i < n; ++i) {
    malachite::Validator v;
    wire::View pk = r.raw(32);
    v.public_key.assign(pk.begin(), pk.end());
    v.address = v.public_key;
    v.voting_power = r.u64();
    vs.push_back(std::move(v));
  }
  return vs;
}

void put_attestations(wire::Writer& w, const std::vector<Attestation>& atts) {
  w.count(atts.size());
  for (const auto& a : atts) {
    w.u64(a.height);
    w.raw(wire::View(a.app_hash.data(), a.app_hash.size()));
    w.raw(wire::View(a.signer.data(), a.signer.size()));
    w.raw(wire::View(a.sig.data(), a.sig.size()));
  }
}

std::vector<Attestation> get_attestations(wire::Reader& r) {
  std::vector<Attestation> out;
  size_t n = r.count();
  for (size_t i = 0; i < n; ++i) {
    Attestation a;
    a.height = r.u64();
    std::memcpy(a.app_hash.data(), r.raw(32).data(), 32);
    std::memcpy(a.signer.data(), r.raw(32).data(), 32);
    std::memcpy(a.sig.data(), r.raw(64).data(), 64);
    out.push_back(a);
  }
  return out;
}

// height ++ app_hash ++ next_set ++ next_set2, no attestations.
void put_checkpoint_core(wire::Writer& w, const SnapshotCheckpoint& c) {
  w.u64(c.height);
  w.raw(wire::View(c.app_hash.data(), c.app_hash.size()));
  put_vset(w, c.next_set);
  put_vset(w, c.next_set2);
}

} // namespace

Hash checkpoint_content_key(const SnapshotCheckpoint& c) {
  wire::Bytes buf;
  wire::Writer w(buf);
  put_checkpoint_core(w, c);
  return sha256(wire::View(buf.data(), buf.size()));
}

bool checkpoint_has_quorum(const SnapshotCheckpoint& c, const malachite::ValidatorSet& trusted) {
  uint64_t total = 0;
  for (const auto& v : trusted) total += v.voting_power ? v.voting_power : 1;
  const wire::Bytes msg = attestation_bytes(c.height, c.app_hash);
  std::set<PubKey> counted;
  uint64_t got = 0;
  for (const auto& a : c.attestations) {
    if (a.height != c.height || !(a.app_hash == c.app_hash)) continue;
    if (counted.count(a.signer)) continue;
    uint64_t power = 0;
    for (const auto& v : trusted) {
      if (v.public_key.size() == 32 && std::memcmp(v.public_key.data(), a.signer.data(), 32) == 0) {
        power = v.voting_power ? v.voting_power : 1;
        break;
      }
    }
    if (power == 0) continue;
    if (!hyle::verify(a.signer, msg, a.sig)) continue;
    counted.insert(a.signer);
    got += power;
  }
  return got * 3 > total * 2;
}

wire::Bytes encode_checkpoint(const SnapshotCheckpoint& c) {
  wire::Bytes out;
  wire::Writer w(out);
  put_checkpoint_core(w, c);
  put_attestations(w, c.attestations);
  return out;
}

SnapshotCheckpoint decode_checkpoint(wire::View v) {
  wire::Reader r(v);
  SnapshotCheckpoint c;
  c.height = r.u64();
  std::memcpy(c.app_hash.data(), r.raw(32).data(), 32);
  c.next_set = get_vset(r);
  c.next_set2 = get_vset(r);
  c.attestations = get_attestations(r);
  if (!r.empty()) throw wire::Error("checkpoint: trailing bytes");
  return c;
}

wire::Bytes encode_state_blob(wire::View governance, wire::View app) {
  wire::Bytes out;
  wire::Writer w(out);
  w.bytes(governance);
  w.bytes(app);
  return out;
}

StateBlob decode_state_blob(wire::View v) {
  wire::Reader r(v);
  StateBlob b;
  wire::View gov = r.bytes();
  b.governance.assign(gov.begin(), gov.end());
  wire::View app = r.bytes();
  b.app.assign(app.begin(), app.end());
  if (!r.empty()) throw wire::Error("state blob: trailing bytes");
  return b;
}

} // namespace hyle
