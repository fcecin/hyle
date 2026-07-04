#ifndef HYLE_LEDGER_H
#define HYLE_LEDGER_H

#include <hyle/core/crypto.h>
#include <hyle/core/state_machine.h>
#include <hyle/core/wire.h>
#include <hyle/services/kv/pow.h>

#include <boost/container_hash/hash.hpp>
#include <boost/unordered/unordered_flat_map.hpp>
#include <boost/unordered/unordered_flat_set.hpp>

#include <cstdint>
#include <memory>
#include <vector>

namespace hyle {

// `seq` must equal the from-cell's current seq at apply; a committed transfer cannot be replayed.
struct XferOp {
  PubKey from{};
  PubKey to{};
  uint64_t amount = 0;
  uint64_t seq = 0;
  Sig sig{};
};

struct EvictOp {
  PubKey key{};
  PubKey culler{};
};

enum class NameKind : uint8_t { Register = 0, Update = 1, Give = 2, Release = 3 };
struct NameOp {
  NameKind kind = NameKind::Register;
  PubKey owner{};
  wire::Bytes name;
  uint64_t version = 0;
  wire::Bytes data;       // Register/Update: content; Give: 32-byte new owner; Release: none
  Sig sig{};
};

struct MintOp {
  PubKey beneficiary{};
  uint64_t nonce = 0;
  Hash solution{};
};

struct MintConfig {
  bool enabled = false;
  uint64_t capacity = 4096;
  unsigned min_diff = 8;
  uint64_t reward_base = 1;
  Hash genesis_key{};
};

class Ledger : public StateMachine {
public:
  static constexpr uint64_t REWARD = 100;
  static constexpr uint64_t BOUNTY = 10;
  static constexpr unsigned MINT_REWARD_MAX_DIFF = 40;

  explicit Ledger(uint64_t rent_rate = 0, MintConfig mint = {},
                  std::unique_ptr<PowVerifier> verifier = nullptr)
      : rate_(rent_rate), mint_(mint),
        verifier_(mint.enabled
                      ? (verifier ? std::move(verifier)
                                  : std::unique_ptr<PowVerifier>(new Sha256PowVerifier()))
                      : std::move(verifier)),
        mint_key_(mint.genesis_key), mint_acc_(mint.genesis_key) {}

  void submit(XferOp op) { pending_xfer_.push_back(op); }
  void submit_evict(const PubKey& key, const PubKey& culler) {
    pending_evict_.push_back(EvictOp{key, culler});
  }
  void submit_name(NameOp op) { pending_name_.push_back(std::move(op)); }
  void submit_mint(MintOp op) { pending_mint_.push_back(op); }

  wire::Bytes build_payload(uint64_t height) override;
  bool validate_payload(wire::View payload) override;
  void apply_payload(const ApplyContext& ctx, wire::View payload) override;
  wire::Bytes snapshot() const override;
  void restore(wire::View bytes) override;

  uint64_t balance(const PubKey& k) const;
  bool exists(const PubKey& k) const { return cells_.count(k) != 0; }
  uint64_t total() const;
  size_t accounts() const { return cells_.size(); }

  static Hash name_key(wire::View name) { return sha256(name); }
  bool has_name(wire::View name) const;
  PubKey name_owner(wire::View name) const;
  uint64_t name_version(wire::View name) const;
  wire::Bytes name_content(wire::View name) const;

  bool mint_enabled() const { return mint_.enabled; }
  const Hash& mint_key() const { return mint_key_; }
  uint64_t mint_fill() const { return mint_fill_; }
  size_t mint_seen_count() const { return mint_seen_.size(); }
  uint64_t mint_reward(unsigned difficulty) const;
  static MintOp make_mint(const PowVerifier& v, const Hash& epoch_key, const PubKey& beneficiary,
                          unsigned min_diff, uint64_t start_nonce = 0);

  static XferOp make_transfer(const KeyPair& from, const PubKey& to, uint64_t amount,
                              uint64_t seq = 0);
  static wire::Bytes xfer_sign_bytes(const PubKey& from, const PubKey& to, uint64_t amount,
                                     uint64_t seq);
  uint64_t account_seq(const PubKey& k) const;
  static wire::Bytes name_sign_bytes(NameKind kind, wire::View name, uint64_t version,
                                     wire::View data);
  static NameOp make_register(const KeyPair& owner, wire::View name, wire::View content);
  static NameOp make_update(const KeyPair& owner, wire::View name, uint64_t version,
                            wire::View content);
  static NameOp make_give(const KeyPair& owner, wire::View name, uint64_t version,
                          const PubKey& new_owner);
  static NameOp make_release(const KeyPair& owner, wire::View name, uint64_t version);

private:
  struct Cell {
    uint64_t balance = 0;
    uint64_t last_charged = 0;
    uint64_t seq = 0;  // replay guard
    bool named = false;
    PubKey owner{};
    uint64_t version = 0;
    wire::Bytes content;
  };
  uint64_t rent_owed(const Cell& c, uint64_t height) const;
  void roll(Cell& c, uint64_t height) const;
  const Cell* find_named(wire::View name) const;
  bool apply_mint(const MintOp& o, uint64_t height);
  void mint_rotate_if_full();

  uint64_t rate_;
  boost::unordered_flat_map<PubKey, Cell, boost::hash<PubKey>> cells_;
  std::vector<XferOp> pending_xfer_;
  std::vector<EvictOp> pending_evict_;
  std::vector<NameOp> pending_name_;

  MintConfig mint_;
  std::unique_ptr<PowVerifier> verifier_;
  std::vector<MintOp> pending_mint_;
  Hash mint_key_{};
  Hash mint_acc_{};
  uint64_t mint_fill_ = 0;
  boost::unordered_flat_set<Hash, boost::hash<Hash>> mint_seen_;
};

} // namespace hyle

#endif
