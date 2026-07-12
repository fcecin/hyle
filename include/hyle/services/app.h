#ifndef HYLE_SERVICES_APP_H
#define HYLE_SERVICES_APP_H

#include <hyle/core/state_machine.h>
#include <hyle/core/wire.h>
#include <hyle/services/kv/pow.h>
#include <hyle/services/kv/state.h>
#include <hyle/services/config.h>
#include <hyle/services/genesis.h>
#include <hyle/services/mempool.h>
#include <hyle/services/ops.h>
#include <hyle/services/schema.h>

#include <boost/container_hash/hash.hpp>
#include <boost/unordered/unordered_flat_set.hpp>

#include <boost/unordered/unordered_flat_map.hpp>

#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

namespace hyle::services {

// The economy schema is built on the kv facility (hyle::services::kv): typed cells over its
// generic State. Pull in the types it uses -- not kv's own op codec, which would clash with
// the economy's encode_ops/decode_ops.
using kv::State;
using kv::PowVerifier;
using kv::Sha256PowVerifier;

struct TxResult {
  uint64_t height = 0;
  bool applied = false;
};

struct CommitEvent {
  uint64_t height = 0;
  uint64_t timestamp = 0;
  PubKey proposer{};
  std::vector<std::pair<Hash, bool>> txs;
  std::vector<PubKey> changed_accounts;
};

class App : public StateMachine {
public:
  explicit App(Config cfg = {}, std::unique_ptr<PowVerifier> verifier = nullptr,
               std::string chain_id = {}, std::size_t mempool_capacity = 8192);

  static App from_genesis(const Genesis& g, std::size_t mempool_capacity = 8192);
  void seed_account(const PubKey& k, uint64_t balance);

  wire::Bytes build_payload(uint64_t height) override;
  bool validate_payload(wire::View payload) override;
  void apply_payload(const ApplyContext& ctx, wire::View payload) override;
  void on_validators_removed(const std::vector<PubKey>& removed) override;
  wire::Bytes snapshot() const override;
  void restore(wire::View bytes) override;

  void submit_mint(MintOp op) { pending_.mints.push_back(op); }
  void submit_transfer(TransferOp op) { pending_.transfers.push_back(std::move(op)); }
  void submit_entry(EntryOp op) { pending_.entries.push_back(std::move(op)); }
  void submit_sudo(SudoOp op) { pending_.sudos.push_back(std::move(op)); }

  Admit admit_transfer(const TransferOp& op) {
    return mempool_.admit_transfer(op, sequence(op.from), balance(op.from));
  }
  Admit admit_entry(const EntryOp& op) {
    if (op.kind == EntryKind::Rip) {
      Entry e;
      if (!load_entry(wire::View(op.name.data(), op.name.size()), e)) return Admit::BadShape;
    }
    return mempool_.admit_entry(op, sequence(op.signer), balance(op.signer));
  }
  Admit admit_mint(const MintOp& op) {
    if (mint_seen_.count(op.solution) != 0) return Admit::Duplicate;
    return mempool_.admit_mint(op);
  }
  Admit admit_sudo(const SudoOp& op) {
    return mempool_.admit_sudo(op, sequence(op.signer), balance(op.signer));
  }
  const Mempool& mempool() const { return mempool_; }

  const State& store() const { return store_; }
  bool account_exists(const PubKey& k) const;
  uint64_t balance(const PubKey& k) const;
  uint64_t sequence(const PubKey& k) const;
  const Config& config() const { return cfg_; }
  const std::string& chain_id() const { return chain_id_; }
  const Hash& mint_key() const { return mint_key_; }
  size_t mint_seen_count() const { return mint_seen_.size(); }
  uint64_t mint_reward(unsigned difficulty) const;
  bool entry_exists(wire::View name) const;
  uint64_t entry_balance(wire::View name) const;
  PubKey entry_owner(wire::View name) const;
  wire::Bytes entry_payload(wire::View name) const;
  bool entry_info(wire::View name, Entry& out) const { return load_entry(name, out); }
  uint64_t last_timestamp() const { return last_timestamp_; }
  void set_now_fn(std::function<uint64_t()> fn) { now_fn_ = std::move(fn); }

  // Credit created by sudo out of the mint sentinel, lifetime.
  uint64_t sudo_minted() const { return sudo_minted_; }
  // A member's live proposal, if any. approvals counts only current-member votes.
  bool pending_info(const PubKey& proposer, Pending& out) const { return load_pending(proposer, out); }
  unsigned pending_approvals(const Pending& p, const std::vector<PubKey>& members) const;

  bool tx_result(const Hash& id, TxResult& out) const;
  size_t tx_result_count() const { return results_.size(); }
  void add_on_commit(std::function<void(const CommitEvent&)> fn) {
    commit_observers_.push_back(std::move(fn));
  }

private:
  bool apply_mint(const MintOp& o);
  bool apply_transfer(const TransferOp& o, uint64_t now);
  static bool valid_transfer_shape(const TransferOp& o);
  bool apply_entry(const EntryOp& o, uint64_t now);
  bool apply_sudo(const SudoOp& o, const ApplyContext& ctx, uint64_t now);
  // The vote that reaches quorum runs the act here, with the act's own guards waived.
  void execute_sudo(wire::View inner, uint64_t now);
  bool sudo_transfer(const TransferOp& o, uint64_t now);
  bool sudo_entry(const EntryOp& o, uint64_t now);
  void credit_dest(wire::View to, uint64_t amount, uint64_t now, const PubKey& owner_if_new);
  void mint_rotate_if_full();
  Account load_account(const PubKey& k) const;
  void store_account(const PubKey& k, const Account& a);
  bool load_entry(wire::View name, Entry& out) const;
  void store_entry(wire::View name, const Entry& e);
  void erase_entry(wire::View name);
  bool load_pending(const PubKey& proposer, Pending& out) const;
  void store_pending(const PubKey& proposer, const Pending& p);
  void erase_pending(const PubKey& proposer);
  uint64_t rent_owed(wire::View name, const Entry& e, uint64_t now) const;
  void roll_rent(wire::View name, Entry& e, uint64_t now) const;

  wire::View chain_v() const {
    return wire::View(reinterpret_cast<const uint8_t*>(chain_id_.data()), chain_id_.size());
  }

  State store_;
  Config cfg_;
  std::string chain_id_;
  std::unique_ptr<PowVerifier> verifier_;
  Decoded pending_;
  Mempool mempool_;

  Hash mint_key_{};
  Hash mint_acc_{};
  uint64_t mint_fill_ = 0;
  boost::unordered_flat_set<Hash, boost::hash<Hash>> mint_seen_;

  uint64_t last_timestamp_ = 0;
  uint64_t sudo_minted_ = 0;
  std::function<uint64_t()> now_fn_;

  boost::unordered_flat_map<Hash, TxResult, boost::hash<Hash>> results_;
  std::deque<Hash> results_order_;
  size_t results_cap_ = 1u << 16;
  std::vector<std::function<void(const CommitEvent&)>> commit_observers_;
  std::vector<PubKey>* dirty_ = nullptr;
};

} // namespace hyle::services

#endif
