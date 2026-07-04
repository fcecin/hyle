#include <hyle/services/ops.h>

#include <cstring>

namespace hyle::morphe {

namespace {
void put_key(wire::Writer& w, const PubKey& k) { w.raw(wire::View(k.data(), k.size())); }
PubKey get_key(wire::Reader& r) {
  PubKey k{};
  std::memcpy(k.data(), r.raw(32).data(), 32);
  return k;
}
void put_hash(wire::Writer& w, const Hash& h) { w.raw(wire::View(h.data(), h.size())); }
Hash get_hash(wire::Reader& r) {
  Hash h{};
  std::memcpy(h.data(), r.raw(32).data(), 32);
  return h;
}
} // namespace

wire::Bytes encode_ops(const Decoded& d) {
  wire::Bytes out;
  wire::Writer w(out);
  w.u64(d.timestamp);
  w.count(d.mints.size());
  for (const auto& o : d.mints) {
    put_key(w, o.beneficiary);
    w.u64(o.nonce);
    put_hash(w, o.solution);
    w.raw(wire::View(o.sig.data(), o.sig.size()));
  }
  w.count(d.transfers.size());
  for (const auto& o : d.transfers) {
    put_key(w, o.from);
    w.bytes(wire::View(o.to.data(), o.to.size()));
    w.u64(o.amount);
    w.u64(o.seq);
    w.raw(wire::View(o.sig.data(), o.sig.size()));
  }
  w.count(d.entries.size());
  for (const auto& o : d.entries) {
    w.u8(static_cast<uint8_t>(o.kind));
    put_key(w, o.signer);
    w.bytes(wire::View(o.name.data(), o.name.size()));
    w.u64(o.seq);
    w.u64(o.amount);
    put_key(w, o.aux);
    w.bytes(wire::View(o.payload.data(), o.payload.size()));
    w.raw(wire::View(o.sig.data(), o.sig.size()));
  }
  return out;
}

Decoded decode_ops(wire::View in) {
  wire::Reader r(in);
  Decoded d;
  d.timestamp = r.u64();
  size_t nm = r.count();
  for (size_t i = 0; i < nm; ++i) {
    MintOp o;
    o.beneficiary = get_key(r);
    o.nonce = r.u64();
    o.solution = get_hash(r);
    std::memcpy(o.sig.data(), r.raw(64).data(), 64);
    d.mints.push_back(o);
  }
  size_t nt = r.count();
  for (size_t i = 0; i < nt; ++i) {
    TransferOp o;
    o.from = get_key(r);
    wire::View to = r.bytes();
    o.to.assign(to.begin(), to.end());
    o.amount = r.u64();
    o.seq = r.u64();
    std::memcpy(o.sig.data(), r.raw(64).data(), 64);
    d.transfers.push_back(std::move(o));
  }
  size_t ne = r.count();
  for (size_t i = 0; i < ne; ++i) {
    EntryOp o;
    const uint8_t k = r.u8();
    if (k > static_cast<uint8_t>(EntryKind::Rip)) throw wire::Error("morphe: entry kind out of range");
    o.kind = static_cast<EntryKind>(k);
    o.signer = get_key(r);
    wire::View namev = r.bytes();
    o.name.assign(namev.begin(), namev.end());
    o.seq = r.u64();
    o.amount = r.u64();
    o.aux = get_key(r);
    wire::View pl = r.bytes();
    o.payload.assign(pl.begin(), pl.end());
    std::memcpy(o.sig.data(), r.raw(64).data(), 64);
    d.entries.push_back(std::move(o));
  }
  if (!r.empty()) throw wire::Error("morphe: ops batch has trailing bytes");
  return d;
}

namespace {
Hash id_from(wire::View sign_bytes, const Sig& sig) {
  wire::Bytes buf(sign_bytes.begin(), sign_bytes.end());
  buf.insert(buf.end(), sig.begin(), sig.end());
  return sha256(wire::View(buf.data(), buf.size()));
}
}

Hash tx_id(wire::View chain_id, const MintOp& o) {
  const wire::Bytes sb = mint_sign_bytes(chain_id, o.beneficiary, o.nonce, o.solution);
  return id_from(wire::View(sb.data(), sb.size()), o.sig);
}
Hash tx_id(wire::View chain_id, const TransferOp& o) {
  const wire::Bytes sb =
      xfer_sign_bytes(chain_id, o.from, wire::View(o.to.data(), o.to.size()), o.amount, o.seq);
  return id_from(wire::View(sb.data(), sb.size()), o.sig);
}
Hash tx_id(wire::View chain_id, const EntryOp& o) {
  const wire::Bytes sb =
      entry_sign_bytes(chain_id, o.kind, o.signer, wire::View(o.name.data(), o.name.size()), o.seq,
                       o.amount, o.aux, wire::View(o.payload.data(), o.payload.size()));
  return id_from(wire::View(sb.data(), sb.size()), o.sig);
}

wire::Bytes mint_sign_bytes(wire::View chain_id, const PubKey& beneficiary, uint64_t nonce,
                            const Hash& solution) {
  wire::Bytes out;
  wire::Writer w(out);
  w.str("MORPHE_MINT_V1");
  w.bytes(chain_id);
  w.raw(wire::View(beneficiary.data(), beneficiary.size()));
  w.u64(nonce);
  w.raw(wire::View(solution.data(), solution.size()));
  return out;
}

wire::Bytes xfer_sign_bytes(wire::View chain_id, const PubKey& from, wire::View to, uint64_t amount,
                            uint64_t seq) {
  wire::Bytes out;
  wire::Writer w(out);
  w.str("MORPHE_XFER_V1");
  w.bytes(chain_id);
  w.raw(wire::View(from.data(), from.size()));
  w.bytes(to);
  w.u64(amount);
  w.u64(seq);
  return out;
}

TransferOp make_transfer(const KeyPair& from, wire::View to, uint64_t amount, uint64_t seq,
                         wire::View chain_id) {
  TransferOp o;
  o.from = from.pub;
  o.to.assign(to.begin(), to.end());
  o.amount = amount;
  o.seq = seq;
  wire::Bytes sb = xfer_sign_bytes(chain_id, o.from, to, amount, seq);
  o.sig = from.sign(wire::View(sb.data(), sb.size()));
  return o;
}

MintOp make_mint(const PowVerifier& v, const Hash& epoch_key, const KeyPair& beneficiary,
                 unsigned min_diff, uint64_t start_nonce, wire::View chain_id) {
  MintOp o;
  o.beneficiary = beneficiary.pub;
  for (uint64_t nonce = start_nonce;; ++nonce) {
    Hash sol = v.hash(epoch_key, beneficiary.pub, nonce);
    if (pow_difficulty(sol) >= min_diff) {
      o.nonce = nonce;
      o.solution = sol;
      break;
    }
  }
  wire::Bytes sb = mint_sign_bytes(chain_id, o.beneficiary, o.nonce, o.solution);
  o.sig = beneficiary.sign(wire::View(sb.data(), sb.size()));
  return o;
}

wire::Bytes entry_sign_bytes(wire::View chain_id, EntryKind kind, const PubKey& signer, wire::View name,
                             uint64_t seq, uint64_t amount, const PubKey& aux, wire::View payload) {
  wire::Bytes out;
  wire::Writer w(out);
  w.str("MORPHE_ENTRY_V1");
  w.bytes(chain_id);
  w.u8(static_cast<uint8_t>(kind));
  w.raw(wire::View(signer.data(), signer.size()));
  w.bytes(name);
  w.u64(seq);
  w.u64(amount);
  w.raw(wire::View(aux.data(), aux.size()));
  w.bytes(payload);
  return out;
}

namespace {
EntryOp signed_entry(EntryKind kind, const KeyPair& owner, wire::View name, uint64_t seq,
                     uint64_t amount, const PubKey& aux, wire::View payload, wire::View chain_id) {
  EntryOp o;
  o.kind = kind;
  o.signer = owner.pub;
  o.name.assign(name.begin(), name.end());
  o.seq = seq;
  o.amount = amount;
  o.aux = aux;
  o.payload.assign(payload.begin(), payload.end());
  wire::Bytes sb = entry_sign_bytes(chain_id, kind, o.signer, name, seq, amount, aux, payload);
  o.sig = owner.sign(wire::View(sb.data(), sb.size()));
  return o;
}
} // namespace

EntryOp make_entry_put(const KeyPair& owner, wire::View name, uint64_t seq, uint64_t fund,
                       wire::View payload, wire::View chain_id) {
  return signed_entry(EntryKind::Put, owner, name, seq, fund, PubKey{}, payload, chain_id);
}
EntryOp make_entry_del(const KeyPair& owner, wire::View name, uint64_t seq, wire::View chain_id) {
  return signed_entry(EntryKind::Del, owner, name, seq, 0, PubKey{}, wire::View{}, chain_id);
}
EntryOp make_entry_give(const KeyPair& owner, wire::View name, uint64_t seq, const PubKey& new_owner,
                        wire::View chain_id) {
  return signed_entry(EntryKind::Give, owner, name, seq, 0, new_owner, wire::View{}, chain_id);
}
EntryOp make_entry_rip(wire::View name, const PubKey& culler) {
  EntryOp o;
  o.kind = EntryKind::Rip;
  o.name.assign(name.begin(), name.end());
  o.aux = culler;
  return o;
}

} // namespace hyle::morphe
