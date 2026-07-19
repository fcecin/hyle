#include <hyle/services/sync.h>

#include <cstring>

namespace hyle::services {

namespace {

void put_vset(wire::Writer& w, const malachite::ValidatorSet& vs) {
  w.count(vs.size());
  for (const auto& v : vs) {
    if (v.public_key.size() != 32) throw wire::Error("sync: validator key must be 32 bytes");
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

void put_snapshot_content(wire::Writer& w, const Snapshot& s) {
  w.u64(s.height);
  w.bytes(wire::View(s.governance.data(), s.governance.size()));
  w.bytes(wire::View(s.app.data(), s.app.size()));
  put_vset(w, s.next_set);
  put_vset(w, s.next_set2);
}

void get_snapshot_content(wire::Reader& r, Snapshot& s) {
  s.height = r.u64();
  wire::View gov = r.bytes();
  s.governance.assign(gov.begin(), gov.end());
  wire::View app = r.bytes();
  s.app.assign(app.begin(), app.end());
  s.next_set = get_vset(r);
  s.next_set2 = get_vset(r);
}

} // namespace

wire::Bytes encode_sync_blocks_req(const SyncBlocksReq& r) {
  wire::Bytes out;
  wire::Writer w(out);
  w.u64(r.from);
  w.u64(r.nonce);
  return out;
}

SyncBlocksReq decode_sync_blocks_req(wire::View v) {
  wire::Reader rd(v);
  SyncBlocksReq r;
  r.from = rd.u64();
  r.nonce = rd.u64();
  if (!rd.empty()) throw wire::Error("sync: trailing bytes");
  return r;
}

wire::Bytes encode_sync_blocks_resp(const SyncBlocksResp& r) {
  wire::Bytes out;
  wire::Writer w(out);
  w.u64(r.nonce);
  w.u64(r.head);
  w.count(r.blocks.size());
  for (const auto& b : r.blocks) {
    w.u64(b.height);
    w.raw(wire::View(b.proposer.data(), b.proposer.size()));
    w.bytes(wire::View(b.value.data(), b.value.size()));
    w.bytes(wire::View(b.certificate.data(), b.certificate.size()));
  }
  return out;
}

SyncBlocksResp decode_sync_blocks_resp(wire::View v) {
  wire::Reader rd(v);
  SyncBlocksResp r;
  r.nonce = rd.u64();
  r.head = rd.u64();
  size_t n = rd.count();
  for (size_t i = 0; i < n; ++i) {
    SyncBlock b;
    b.height = rd.u64();
    std::memcpy(b.proposer.data(), rd.raw(32).data(), 32);
    wire::View val = rd.bytes();
    b.value.assign(val.begin(), val.end());
    wire::View cert = rd.bytes();
    b.certificate.assign(cert.begin(), cert.end());
    r.blocks.push_back(std::move(b));
  }
  if (!rd.empty()) throw wire::Error("sync: trailing bytes");
  return r;
}

wire::Bytes encode_sync_snap_req(const SyncSnapReq& r) {
  wire::Bytes out;
  wire::Writer w(out);
  w.u64(r.have);
  w.u64(r.nonce);
  return out;
}

SyncSnapReq decode_sync_snap_req(wire::View v) {
  wire::Reader rd(v);
  SyncSnapReq r;
  r.have = rd.u64();
  r.nonce = rd.u64();
  if (!rd.empty()) throw wire::Error("sync: trailing bytes");
  return r;
}

wire::Bytes encode_sync_snap_resp(const SyncSnapResp& r) {
  wire::Bytes out;
  wire::Writer w(out);
  w.u64(r.nonce);
  put_snapshot_content(w, r.snap);
  w.count(r.snap.attestations.size());
  for (const auto& a : r.snap.attestations) {
    w.u64(a.height);
    w.raw(wire::View(a.app_hash.data(), a.app_hash.size()));
    w.raw(wire::View(a.signer.data(), a.signer.size()));
    w.raw(wire::View(a.sig.data(), a.sig.size()));
  }
  return out;
}

SyncSnapResp decode_sync_snap_resp(wire::View v) {
  wire::Reader rd(v);
  SyncSnapResp r;
  r.nonce = rd.u64();
  get_snapshot_content(rd, r.snap);
  size_t n = rd.count();
  for (size_t i = 0; i < n; ++i) {
    Attestation a;
    a.height = rd.u64();
    std::memcpy(a.app_hash.data(), rd.raw(32).data(), 32);
    std::memcpy(a.signer.data(), rd.raw(32).data(), 32);
    std::memcpy(a.sig.data(), rd.raw(64).data(), 64);
    r.snap.attestations.push_back(a);
  }
  if (!rd.empty()) throw wire::Error("sync: trailing bytes");
  return r;
}

Hash snapshot_content_key(const Snapshot& s) {
  wire::Bytes buf;
  wire::Writer w(buf);
  put_snapshot_content(w, s);
  return sha256(wire::View(buf.data(), buf.size()));
}

} // namespace hyle::services
