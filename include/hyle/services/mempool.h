#ifndef HYLE_SERVICES_MEMPOOL_H
#define HYLE_SERVICES_MEMPOOL_H

#include <hyle/core/crypto.h>
#include <hyle/services/config.h>
#include <hyle/services/ops.h>

#include <boost/container_hash/hash.hpp>
#include <boost/unordered/unordered_flat_map.hpp>
#include <boost/unordered/unordered_flat_set.hpp>

#include <cstdint>
#include <string>

namespace hyle::services {

enum class Admit {
  Ok,
  Full,
  BadShape,
  BadSig,
  SeqStale,
  SeqGap,
  InsufficientFunds,
  Duplicate,
};
const char* admit_reason(Admit a);

class Mempool {
public:
  explicit Mempool(Config cfg, size_t capacity = 8192, std::string chain_id = {})
      : cfg_(cfg), cap_(capacity), chain_id_(std::move(chain_id)) {}

  Admit admit_transfer(const TransferOp& op, uint64_t committed_seq, uint64_t committed_balance);
  Admit admit_entry(const EntryOp& op, uint64_t committed_seq, uint64_t committed_balance);
  Admit admit_sudo(const SudoOp& op, uint64_t committed_seq, uint64_t committed_balance);

  Decoded drain(size_t max);

  Decoded snapshot() const;

  size_t size() const { return order_.size(); }
  bool empty() const { return order_.empty(); }
  const Config& config() const { return cfg_; }

private:
  enum class Kind : uint8_t { Transfer, Entry, Sudo };
  struct Slot { Kind kind; size_t idx; };

  Hash id_of(wire::View sign_bytes, const Sig& sig) const;
  bool seen(const Hash& id) const { return seen_.count(id) != 0; }
  wire::View chain_v() const {
    return wire::View(reinterpret_cast<const uint8_t*>(chain_id_.data()), chain_id_.size());
  }

  Config cfg_;
  size_t cap_;
  std::string chain_id_;
  std::vector<TransferOp> transfers_;
  std::vector<EntryOp> entries_;
  std::vector<SudoOp> sudos_;
  std::vector<Slot> order_;
  boost::unordered_flat_set<Hash, boost::hash<Hash>> seen_;
  boost::unordered_flat_map<PubKey, uint64_t, boost::hash<PubKey>> next_seq_;
  boost::unordered_flat_map<PubKey, uint64_t, boost::hash<PubKey>> debit_;
};

} // namespace hyle::services

#endif
