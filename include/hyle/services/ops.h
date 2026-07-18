#ifndef HYLE_SERVICES_OPS_H
#define HYLE_SERVICES_OPS_H

#include <hyle/core/crypto.h>
#include <hyle/core/wire.h>

#include <cstdint>
#include <vector>

namespace hyle::services {

// `to` is the full destination key ('a'+pubkey or 'e'+name).
struct TransferOp {
  PubKey from{};
  wire::Bytes to;
  uint64_t amount = 0;
  uint64_t seq = 0;
  bool max = false;   // send min(amount, available); never fails on insufficient funds
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

// Governance runs an act with its guards waived (no signature, sequence, fee, or ownership
// check), authorized by a member supermajority collected on chain in a 'g' cell (see Pending).
// Propose opens the cell and casts the proposer's vote; Approve adds one; the vote reaching
// quorum executes the act in that block.
enum class SudoKind : uint8_t {
  Propose = 0,
  Approve = 1,
};

// inner is an op batch carried on Propose only; Approve names the proposal by proposer.
// inner_hash binds a vote to the exact act.
struct SudoOp {
  SudoKind kind = SudoKind::Propose;
  PubKey signer{};
  uint64_t seq = 0;
  PubKey proposer{};   // == signer on Propose
  Hash inner_hash{};
  wire::Bytes inner;   // Propose only
  Sig sig{};
};

struct Decoded {
  uint64_t timestamp = 0;
  std::vector<TransferOp> transfers;
  std::vector<EntryOp> entries;
  std::vector<SudoOp> sudos;
};

// [timestamp][count(transfers)][transfers][count(entries)][entries][count(sudos)][sudos].
wire::Bytes encode_ops(const Decoded& d);
Decoded decode_ops(wire::View in);

Hash tx_id(wire::View chain_id, const TransferOp& o);
Hash tx_id(wire::View chain_id, const EntryOp& o);
Hash tx_id(wire::View chain_id, const SudoOp& o);

wire::Bytes xfer_sign_bytes(wire::View chain_id, const PubKey& from, wire::View to, uint64_t amount,
                            uint64_t seq, bool max);
wire::Bytes entry_sign_bytes(wire::View chain_id, EntryKind kind, const PubKey& signer, wire::View name,
                             uint64_t seq, uint64_t amount, const PubKey& aux, wire::View payload);

wire::Bytes sudo_sign_bytes(wire::View chain_id, SudoKind kind, const PubKey& signer, uint64_t seq,
                            const PubKey& proposer, const Hash& inner_hash);

TransferOp make_transfer(const KeyPair& from, wire::View to, uint64_t amount, uint64_t seq,
                         wire::View chain_id = {}, bool max = false);

EntryOp make_entry_put(const KeyPair& owner, wire::View name, uint64_t seq, uint64_t fund,
                       wire::View payload, wire::View chain_id = {});
EntryOp make_entry_del(const KeyPair& owner, wire::View name, uint64_t seq, wire::View chain_id = {});
EntryOp make_entry_give(const KeyPair& owner, wire::View name, uint64_t seq, const PubKey& new_owner,
                        wire::View chain_id = {});
EntryOp make_entry_rip(wire::View name, const PubKey& culler);

SudoOp make_sudo_propose(const KeyPair& proposer, uint64_t seq, wire::View inner,
                         wire::View chain_id = {});
SudoOp make_sudo_approve(const KeyPair& voter, uint64_t seq, const PubKey& proposer,
                         const Hash& inner_hash, wire::View chain_id = {});

// A well-formed transfer destination: 'a'+pubkey (33 bytes) or 'e'+name (>= 2 bytes).
bool valid_transfer_dest(wire::View to);

// Whether inner is a runnable sudo act: a non-empty op batch of transfers and entries only
// (no nested sudo), none leaving an entry owned by the mint sentinel. Non-mutating.
bool valid_sudo_inner(wire::View inner);

} // namespace hyle::services

#endif
