#ifndef HYLE_MORPHE_OPS_H
#define HYLE_MORPHE_OPS_H

#include <hyle/core/crypto.h>
#include <hyle/core/wire.h>
#include <hyle/services/kv/pow.h>

#include <cstdint>
#include <vector>

namespace hyle::morphe {

struct MintOp {
  PubKey beneficiary{};
  uint64_t nonce = 0;
  Hash solution{};
  Sig sig{};
};

// `to` is the full destination key ('a'+pubkey or 'e'+name).
struct TransferOp {
  PubKey from{};
  wire::Bytes to;
  uint64_t amount = 0;
  uint64_t seq = 0;
  Sig sig{};
};

enum class EntryKind : uint8_t {
  Put = 0,
  Del = 1,
  Give = 2,
  Rip = 3,
};

// `aux` is the new owner (Give) or the culler (Rip).
struct EntryOp {
  EntryKind kind = EntryKind::Put;
  PubKey signer{};
  wire::Bytes name;
  uint64_t seq = 0;
  uint64_t amount = 0;
  PubKey aux{};
  wire::Bytes payload;
  Sig sig{};
};

struct Decoded {
  uint64_t timestamp = 0;
  std::vector<MintOp> mints;
  std::vector<TransferOp> transfers;
  std::vector<EntryOp> entries;
};

// [timestamp][count(mints)][mints][count(transfers)][transfers][count(entries)][entries].
wire::Bytes encode_ops(const Decoded& d);
Decoded decode_ops(wire::View in);

Hash tx_id(wire::View chain_id, const MintOp& o);
Hash tx_id(wire::View chain_id, const TransferOp& o);
Hash tx_id(wire::View chain_id, const EntryOp& o);

wire::Bytes mint_sign_bytes(wire::View chain_id, const PubKey& beneficiary, uint64_t nonce,
                            const Hash& solution);
wire::Bytes xfer_sign_bytes(wire::View chain_id, const PubKey& from, wire::View to, uint64_t amount,
                            uint64_t seq);
wire::Bytes entry_sign_bytes(wire::View chain_id, EntryKind kind, const PubKey& signer, wire::View name,
                             uint64_t seq, uint64_t amount, const PubKey& aux, wire::View payload);

MintOp make_mint(const PowVerifier& v, const Hash& epoch_key, const KeyPair& beneficiary,
                 unsigned min_diff, uint64_t start_nonce = 0, wire::View chain_id = {});

TransferOp make_transfer(const KeyPair& from, wire::View to, uint64_t amount, uint64_t seq,
                         wire::View chain_id = {});

EntryOp make_entry_put(const KeyPair& owner, wire::View name, uint64_t seq, uint64_t fund,
                       wire::View payload, wire::View chain_id = {});
EntryOp make_entry_del(const KeyPair& owner, wire::View name, uint64_t seq, wire::View chain_id = {});
EntryOp make_entry_give(const KeyPair& owner, wire::View name, uint64_t seq, const PubKey& new_owner,
                        wire::View chain_id = {});
EntryOp make_entry_rip(wire::View name, const PubKey& culler);

} // namespace hyle::morphe

#endif
