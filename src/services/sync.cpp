#include <hyle/services/sync.h>

#include <cstring>

namespace hyle::services {

wire::Bytes encode_checkpoint_req(const CheckpointReq& r) {
  wire::Bytes out;
  wire::Writer w(out);
  w.u64(r.have);
  w.u64(r.nonce);
  return out;
}

CheckpointReq decode_checkpoint_req(wire::View v) {
  wire::Reader rd(v);
  CheckpointReq r;
  r.have = rd.u64();
  r.nonce = rd.u64();
  if (!rd.empty()) throw wire::Error("sync: trailing bytes");
  return r;
}

wire::Bytes encode_blob_req(const BlobReq& r) {
  wire::Bytes out;
  wire::Writer w(out);
  w.u8(r.kind);
  w.u64(r.height);
  w.u64(r.nonce);
  return out;
}

BlobReq decode_blob_req(wire::View v) {
  wire::Reader rd(v);
  BlobReq r;
  r.kind = rd.u8();
  r.height = rd.u64();
  r.nonce = rd.u64();
  if (!rd.empty()) throw wire::Error("sync: trailing bytes");
  return r;
}

wire::Bytes encode_blocks(const std::vector<SyncBlock>& blocks) {
  wire::Bytes out;
  wire::Writer w(out);
  w.count(blocks.size());
  for (const auto& b : blocks) {
    w.u64(b.height);
    w.raw(wire::View(b.proposer.data(), b.proposer.size()));
    w.bytes(wire::View(b.value.data(), b.value.size()));
    w.bytes(wire::View(b.certificate.data(), b.certificate.size()));
  }
  return out;
}

std::vector<SyncBlock> decode_blocks(wire::View v) {
  wire::Reader rd(v);
  std::vector<SyncBlock> out;
  size_t n = rd.count();
  for (size_t i = 0; i < n; ++i) {
    SyncBlock b;
    b.height = rd.u64();
    std::memcpy(b.proposer.data(), rd.raw(32).data(), 32);
    wire::View val = rd.bytes();
    b.value.assign(val.begin(), val.end());
    wire::View cert = rd.bytes();
    b.certificate.assign(cert.begin(), cert.end());
    out.push_back(std::move(b));
  }
  if (!rd.empty()) throw wire::Error("sync: trailing bytes");
  return out;
}

} // namespace hyle::services
