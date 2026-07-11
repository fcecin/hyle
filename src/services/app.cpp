#include <hyle/services/app.h>

#include <hyle/services/kv/ops.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <vector>

namespace hyle::services {

using kv::Op;
using kv::pow_difficulty;

namespace {
uint64_t sat_add(uint64_t a, uint64_t b) { return a > UINT64_MAX - b ? UINT64_MAX : a + b; }
uint64_t sat_mul(uint64_t a, uint64_t b) {
  if (a == 0 || b == 0) return 0;
  return a > UINT64_MAX / b ? UINT64_MAX : a * b;
}
void put_hash(wire::Writer& w, const Hash& h) { w.raw(wire::View(h.data(), h.size())); }
Hash get_hash(wire::Reader& r) {
  Hash h{};
  std::memcpy(h.data(), r.raw(32).data(), 32);
  return h;
}
} // namespace

App::App(Config cfg, std::unique_ptr<PowVerifier> verifier, std::string chain_id)
    : cfg_(cfg),
      chain_id_(std::move(chain_id)),
      verifier_(verifier ? std::move(verifier) : std::unique_ptr<PowVerifier>(new Sha256PowVerifier())),
      mempool_(cfg, 8192, chain_id_),
      mint_key_(cfg.mint_genesis_key),
      mint_acc_(cfg.mint_genesis_key) {
  now_fn_ = [] {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
  };
}

App App::from_genesis(const Genesis& g) {
  App a(g.config, nullptr, g.chain_id);
  for (const auto& alloc : g.allocations) a.seed_account(alloc.first, alloc.second);
  return a;
}

void App::seed_account(const PubKey& k, uint64_t balance) {
  Account acc = load_account(k);
  acc.balance = balance;
  store_account(k, acc);
}

uint64_t App::mint_reward(unsigned difficulty) const { return reward_for(cfg_, difficulty); }

Account App::load_account(const PubKey& k) const {
  const wire::Bytes key = account_key(k);
  const wire::Bytes* v = store_.get(wire::View(key.data(), key.size()));
  if (v == nullptr) return Account{};
  return Account::decode(wire::View(v->data(), v->size()));
}

void App::store_account(const PubKey& k, const Account& a) {
  const wire::Bytes key = account_key(k);
  const wire::Bytes val = a.encode();
  store_.apply(Op::put(wire::View(key.data(), key.size()), wire::View(val.data(), val.size())));
  if (dirty_ != nullptr) dirty_->push_back(k);
}

bool App::account_exists(const PubKey& k) const {
  const wire::Bytes key = account_key(k);
  return store_.get(wire::View(key.data(), key.size())) != nullptr;
}
uint64_t App::balance(const PubKey& k) const { return load_account(k).balance; }
uint64_t App::sequence(const PubKey& k) const { return load_account(k).sequence; }

bool App::apply_mint(const MintOp& o) {
  const unsigned d = pow_difficulty(o.solution);
  const uint64_t reward = mint_reward(d);
  if (reward <= cfg_.fee_mint) return false;
  if (mint_seen_.count(o.solution) != 0) return false;
  const wire::Bytes sb = mint_sign_bytes(chain_v(), o.beneficiary, o.nonce, o.solution);
  if (!verify(o.beneficiary, wire::View(sb.data(), sb.size()), o.sig)) return false;
  if (!(verifier_->hash(mint_key_, o.beneficiary, o.nonce) == o.solution)) return false;

  Account acc = load_account(o.beneficiary);
  acc.balance = sat_add(acc.balance, reward - cfg_.fee_mint);
  store_account(o.beneficiary, acc);

  mint_seen_.insert(o.solution);
  mint_fill_++;
  wire::Bytes fold(mint_acc_.begin(), mint_acc_.end());
  fold.insert(fold.end(), o.solution.begin(), o.solution.end());
  mint_acc_ = sha256(wire::View(fold.data(), fold.size()));
  return true;
}

bool App::valid_transfer_shape(const TransferOp& o) {
  return valid_transfer_dest(wire::View(o.to.data(), o.to.size()));
}

bool App::apply_transfer(const TransferOp& o, uint64_t now) {
  if (!valid_transfer_shape(o)) return false;
  const wire::Bytes sb = xfer_sign_bytes(chain_v(), o.from, wire::View(o.to.data(), o.to.size()), o.amount, o.seq);
  if (!verify(o.from, wire::View(sb.data(), sb.size()), o.sig)) return false;
  if (!account_exists(o.from)) return false;
  Account from = load_account(o.from);
  if (o.seq != from.sequence) return false;
  const uint64_t cost = sat_add(o.amount, cfg_.fee_transfer);
  if (from.balance < cost) return false;
  from.balance -= cost;
  from.sequence++;
  store_account(o.from, from);

  credit_dest(wire::View(o.to.data(), o.to.size()), o.amount, now, o.from);
  return true;
}

void App::credit_dest(wire::View to, uint64_t amount, uint64_t now, const PubKey& owner_if_new) {
  if (to[0] == ACCOUNT_PREFIX) {
    PubKey dest{};
    std::memcpy(dest.data(), to.data() + 1, 32);
    Account a = load_account(dest);
    a.balance = sat_add(a.balance, amount);
    store_account(dest, a);
    return;
  }
  const wire::View name(to.data() + 1, to.size() - 1);
  Entry e;
  if (load_entry(name, e)) {
    roll_rent(name, e, now);
    e.balance = sat_add(e.balance, amount);
  } else {
    e = Entry{};
    e.owner = owner_if_new;
    e.balance = amount;
    e.created = now;
    e.last_modified = now;
    e.last_rent = now;
  }
  store_entry(name, e);
}

bool App::load_entry(wire::View name, Entry& out) const {
  const wire::Bytes key = entry_key(name);
  const wire::Bytes* v = store_.get(wire::View(key.data(), key.size()));
  if (v == nullptr) return false;
  out = Entry::decode(wire::View(v->data(), v->size()));
  return true;
}
void App::store_entry(wire::View name, const Entry& e) {
  const wire::Bytes key = entry_key(name);
  const wire::Bytes val = e.encode();
  store_.apply(Op::put(wire::View(key.data(), key.size()), wire::View(val.data(), val.size())));
}
void App::erase_entry(wire::View name) {
  const wire::Bytes key = entry_key(name);
  store_.apply(Op::del(wire::View(key.data(), key.size())));
}

bool App::load_pending(const PubKey& proposer, Pending& out) const {
  const wire::Bytes key = pending_key(proposer);
  const wire::Bytes* v = store_.get(wire::View(key.data(), key.size()));
  if (v == nullptr) return false;
  out = Pending::decode(wire::View(v->data(), v->size()));
  return true;
}
void App::store_pending(const PubKey& proposer, const Pending& p) {
  const wire::Bytes key = pending_key(proposer);
  const wire::Bytes val = p.encode();
  store_.apply(Op::put(wire::View(key.data(), key.size()), wire::View(val.data(), val.size())));
}
void App::erase_pending(const PubKey& proposer) {
  const wire::Bytes key = pending_key(proposer);
  store_.apply(Op::del(wire::View(key.data(), key.size())));
}

unsigned App::pending_approvals(const Pending& p, const std::vector<PubKey>& members) const {
  unsigned n = 0;
  for (const auto& v : p.voters)
    if (std::find(members.begin(), members.end(), v) != members.end()) ++n;
  return n;
}

void App::on_validators_removed(const std::vector<PubKey>& removed) {
  for (const auto& k : removed) erase_pending(k);  // a departed member cannot use its slot
}

uint64_t App::rent_owed(wire::View name, const Entry& e, uint64_t now) const {
  if (cfg_.rent_rate == 0) return 0;
  const uint64_t elapsed = now > e.last_rent ? now - e.last_rent : 0;
  const uint64_t footprint = 1 + name.size() + Entry::HEADER + e.payload.size();
  return sat_mul(sat_mul(cfg_.rent_rate, footprint), elapsed);
}
void App::roll_rent(wire::View name, Entry& e, uint64_t now) const {
  const uint64_t owed = rent_owed(name, e, now);
  e.balance = owed >= e.balance ? 0 : e.balance - owed;
  e.last_rent = now;
}

bool App::entry_exists(wire::View name) const {
  Entry e;
  return load_entry(name, e);
}
uint64_t App::entry_balance(wire::View name) const {
  Entry e;
  return load_entry(name, e) ? e.balance : 0;
}
PubKey App::entry_owner(wire::View name) const {
  Entry e;
  return load_entry(name, e) ? e.owner : PubKey{};
}
wire::Bytes App::entry_payload(wire::View name) const {
  Entry e;
  return load_entry(name, e) ? e.payload : wire::Bytes{};
}

bool App::apply_entry(const EntryOp& o, uint64_t now) {
  if (o.name.empty()) return false;
  const wire::View name(o.name.data(), o.name.size());

  if (o.kind == EntryKind::Rip) {
    Entry e;
    if (!load_entry(name, e)) return false;
    const uint64_t owed = rent_owed(name, e, now);
    roll_rent(name, e, now);
    if (e.balance != 0 || owed == 0) return false;
    erase_entry(name);
    Account c = load_account(o.aux);
    c.balance = sat_add(c.balance, cfg_.rip_bounty);
    store_account(o.aux, c);
    return true;
  }

  const wire::View payload(o.payload.data(), o.payload.size());
  const wire::Bytes sb = entry_sign_bytes(chain_v(), o.kind, o.signer, name, o.seq, o.amount, o.aux, payload);
  if (!verify(o.signer, wire::View(sb.data(), sb.size()), o.sig)) return false;
  if (!account_exists(o.signer)) return false;
  Account acc = load_account(o.signer);
  if (o.seq != acc.sequence) return false;
  uint64_t need = cfg_.fee_entry;
  if (o.kind == EntryKind::Put) need = sat_add(need, o.amount);
  if (acc.balance < need) return false;

  Entry e;
  const bool exists = load_entry(name, e);

  if (o.kind == EntryKind::Put) {
    if (exists) {
      if (!(e.owner == o.signer)) return false;
      roll_rent(name, e, now);
      e.balance = sat_add(e.balance, o.amount);
      e.last_modified = now;
      e.payload.assign(o.payload.begin(), o.payload.end());
    } else {
      e = Entry{};
      e.owner = o.signer;
      e.balance = o.amount;
      e.created = now;
      e.last_modified = now;
      e.last_rent = now;
      e.payload.assign(o.payload.begin(), o.payload.end());
    }
    store_entry(name, e);
  } else if (o.kind == EntryKind::Del) {
    if (!exists || !(e.owner == o.signer)) return false;
    roll_rent(name, e, now);
    acc.balance = sat_add(acc.balance, e.balance);
    erase_entry(name);
  } else {
    if (!exists || !(e.owner == o.signer)) return false;
    if (o.aux == PubKey{}) return false;
    roll_rent(name, e, now);
    e.owner = o.aux;
    e.last_modified = now;
    store_entry(name, e);
  }

  acc.balance -= need;
  acc.sequence++;
  store_account(o.signer, acc);
  return true;
}

// Sudo effects. The quorum-reaching vote runs the act with its guards waived.

bool App::sudo_transfer(const TransferOp& o, uint64_t now) {
  if (!valid_transfer_shape(o)) return false;
  const wire::View to(o.to.data(), o.to.size());
  const bool mint = is_mint_sentinel(o.from);
  // A mint cannot create an entry (the sentinel would own it, unsignable); only fund one.
  if (mint && to[0] == ENTRY_PREFIX) {
    const wire::View name(to.data() + 1, to.size() - 1);
    if (!entry_exists(name)) return false;
  }
  if (mint) {
    sudo_minted_ = sat_add(sudo_minted_, o.amount);
  } else {
    if (!account_exists(o.from)) return false;
    Account from = load_account(o.from);
    if (from.balance < o.amount) return false;  // moves real funds; only the sentinel mints
    from.balance -= o.amount;
    store_account(o.from, from);
  }
  credit_dest(to, o.amount, now, o.from);
  return true;
}

bool App::sudo_entry(const EntryOp& o, uint64_t now) {
  if (o.name.empty()) return false;
  const wire::View name(o.name.data(), o.name.size());
  Entry e;
  const bool exists = load_entry(name, e);

  if (o.kind == EntryKind::Put) {
    if (is_mint_sentinel(o.signer)) return false;  // would be unownable
    if (exists) {
      roll_rent(name, e, now);
      e.balance = sat_add(e.balance, o.amount);
    } else {
      e = Entry{};
      e.balance = o.amount;
      e.created = now;
      e.last_rent = now;
    }
    e.owner = o.signer;
    e.last_modified = now;
    e.payload.assign(o.payload.begin(), o.payload.end());
    sudo_minted_ = sat_add(sudo_minted_, o.amount);
    store_entry(name, e);
    return true;
  }
  if (!exists) return false;
  if (o.kind == EntryKind::Give) {
    if (is_mint_sentinel(o.aux)) return false;
    roll_rent(name, e, now);
    e.owner = o.aux;
    e.last_modified = now;
    store_entry(name, e);
    return true;
  }
  if (o.kind == EntryKind::Del) {
    roll_rent(name, e, now);
    Account owner = load_account(e.owner);
    owner.balance = sat_add(owner.balance, e.balance);
    store_account(e.owner, owner);
    erase_entry(name);
    return true;
  }
  erase_entry(name);  // Rip: erase, refund no one
  return true;
}

void App::execute_sudo(wire::View inner, uint64_t now) {
  Decoded d;
  try {
    d = decode_ops(inner);
  } catch (const wire::Error&) {
    return;  // it passed valid_sudo_inner when proposed; a decode failure here is a no-op
  }
  for (const auto& o : d.transfers) sudo_transfer(o, now);
  for (const auto& o : d.entries) sudo_entry(o, now);
}

bool App::apply_sudo(const SudoOp& o, const ApplyContext& ctx, uint64_t now) {
  const wire::Bytes sb = sudo_sign_bytes(chain_v(), o.kind, o.signer, o.seq, o.proposer, o.inner_hash);
  if (!verify(o.signer, wire::View(sb.data(), sb.size()), o.sig)) return false;
  // Only a current member may act; its account is created on first act. fee_sudo still gates
  // a member with no balance.
  if (std::find(ctx.members.begin(), ctx.members.end(), o.signer) == ctx.members.end()) return false;
  Account acc = load_account(o.signer);
  if (o.seq != acc.sequence) return false;
  if (acc.balance < cfg_.fee_sudo) return false;

  // Assemble the proposal cell, failing before the fee is charged if the op cannot apply.
  Pending p;
  if (o.kind == SudoKind::Propose) {
    if (o.proposer != o.signer) return false;                     // proposer must be the signer
    if (o.inner_hash != sha256(wire::View(o.inner.data(), o.inner.size()))) return false;
    if (!valid_sudo_inner(wire::View(o.inner.data(), o.inner.size()))) return false;
    // A re-propose of the identical act keeps its votes; a different act or an expired cell
    // starts fresh.
    Pending prev;
    const bool keep = load_pending(o.proposer, prev) &&
                      !(cfg_.sudo_ttl_secs > 0 && now > sat_add(prev.created, cfg_.sudo_ttl_secs)) &&
                      prev.inner == o.inner;
    if (keep) p.voters = prev.voters;
    p.created = now;
    p.add_voter(o.signer);
    p.inner.assign(o.inner.begin(), o.inner.end());
  } else {
    const bool exists = load_pending(o.proposer, p);
    const bool expired =
        exists && cfg_.sudo_ttl_secs > 0 && now > sat_add(p.created, cfg_.sudo_ttl_secs);
    if (expired) { erase_pending(o.proposer); return false; }     // a timeout, cleared on touch
    if (!exists) return false;
    if (o.inner_hash != sha256(wire::View(p.inner.data(), p.inner.size()))) return false;  // stale act
    if (p.has_voted(o.signer)) return false;
    p.add_voter(o.signer);
  }

  acc.balance -= cfg_.fee_sudo;
  acc.sequence++;
  store_account(o.signer, acc);

  if (pending_approvals(p, ctx.members) >= ctx.quorum) {
    execute_sudo(wire::View(p.inner.data(), p.inner.size()), now);
    erase_pending(o.proposer);
  } else {
    store_pending(o.proposer, p);
  }
  return true;
}

void App::mint_rotate_if_full() {
  if (cfg_.mint_capacity > 0 && mint_fill_ >= cfg_.mint_capacity) {
    mint_key_ = sha256(wire::View(mint_acc_.data(), mint_acc_.size()));
    mint_acc_ = mint_key_;
    mint_fill_ = 0;
    mint_seen_.clear();
  }
}

wire::Bytes App::build_payload(uint64_t) {
  {
    static constexpr size_t kBlockOpCap = 4096;
    Decoded md = mempool_.drain(kBlockOpCap);
    for (auto& m : md.mints) pending_.mints.push_back(std::move(m));
    for (auto& t : md.transfers) pending_.transfers.push_back(std::move(t));
    for (auto& e : md.entries) pending_.entries.push_back(std::move(e));
    for (auto& s : md.sudos) pending_.sudos.push_back(std::move(s));
  }
  Decoded d;
  d.timestamp = now_fn_();
  for (const auto& o : pending_.mints) {
    if (mint_reward(pow_difficulty(o.solution)) <= cfg_.fee_mint) continue;
    const wire::Bytes sb = mint_sign_bytes(chain_v(), o.beneficiary, o.nonce, o.solution);
    if (!verify(o.beneficiary, wire::View(sb.data(), sb.size()), o.sig)) continue;
    if (!(verifier_->hash(mint_key_, o.beneficiary, o.nonce) == o.solution)) continue;
    d.mints.push_back(o);
  }
  for (const auto& o : pending_.transfers) {
    if (!valid_transfer_shape(o)) continue;
    const wire::Bytes sb = xfer_sign_bytes(chain_v(), o.from, wire::View(o.to.data(), o.to.size()), o.amount, o.seq);
    if (!verify(o.from, wire::View(sb.data(), sb.size()), o.sig)) continue;
    d.transfers.push_back(o);
  }
  for (const auto& o : pending_.entries) {
    if (o.name.empty()) continue;
    if (o.kind != EntryKind::Rip) {
      const wire::Bytes sb = entry_sign_bytes(chain_v(), o.kind, o.signer, wire::View(o.name.data(), o.name.size()),
                                              o.seq, o.amount, o.aux,
                                              wire::View(o.payload.data(), o.payload.size()));
      if (!verify(o.signer, wire::View(sb.data(), sb.size()), o.sig)) continue;
    }
    d.entries.push_back(o);
  }
  for (const auto& o : pending_.sudos) {
    const wire::Bytes sb = sudo_sign_bytes(chain_v(), o.kind, o.signer, o.seq, o.proposer, o.inner_hash);
    if (!verify(o.signer, wire::View(sb.data(), sb.size()), o.sig)) continue;
    d.sudos.push_back(o);
  }
  pending_.mints.clear();
  pending_.transfers.clear();
  pending_.entries.clear();
  pending_.sudos.clear();
  return encode_ops(d);
}

bool App::validate_payload(wire::View payload) {
  try {
    Decoded d = decode_ops(payload);
    const uint64_t now = now_fn_();
    const uint64_t diff = now > d.timestamp ? now - d.timestamp : d.timestamp - now;
    if (diff > cfg_.pbts_window_secs) return false;
    if (d.timestamp < last_timestamp_) return false;
    for (const auto& o : d.mints) {
      if (mint_reward(pow_difficulty(o.solution)) <= cfg_.fee_mint) return false;
      const wire::Bytes sb = mint_sign_bytes(chain_v(), o.beneficiary, o.nonce, o.solution);
      if (!verify(o.beneficiary, wire::View(sb.data(), sb.size()), o.sig)) return false;
      if (!(verifier_->hash(mint_key_, o.beneficiary, o.nonce) == o.solution)) return false;
    }
    for (const auto& o : d.transfers) {
      if (!valid_transfer_shape(o)) return false;
      const wire::Bytes sb =
          xfer_sign_bytes(chain_v(), o.from, wire::View(o.to.data(), o.to.size()), o.amount, o.seq);
      if (!verify(o.from, wire::View(sb.data(), sb.size()), o.sig)) return false;
    }
    for (const auto& o : d.entries) {
      if (o.kind == EntryKind::Rip) continue;
      const wire::Bytes sb = entry_sign_bytes(chain_v(), o.kind, o.signer, wire::View(o.name.data(), o.name.size()),
                                              o.seq, o.amount, o.aux,
                                              wire::View(o.payload.data(), o.payload.size()));
      if (!verify(o.signer, wire::View(sb.data(), sb.size()), o.sig)) return false;
    }
    for (const auto& o : d.sudos) {
      const wire::Bytes sb =
          sudo_sign_bytes(chain_v(), o.kind, o.signer, o.seq, o.proposer, o.inner_hash);
      if (!verify(o.signer, wire::View(sb.data(), sb.size()), o.sig)) return false;
    }
    return true;
  } catch (const wire::Error&) {
    return false;
  }
}

void App::apply_payload(const ApplyContext& ctx, wire::View payload) {
  Decoded d = decode_ops(payload);
  CommitEvent ev;
  ev.height = ctx.height;
  ev.timestamp = d.timestamp;
  ev.proposer = ctx.proposer;
  std::vector<PubKey> changed;
  dirty_ = &changed;

  auto record = [&](const Hash& id, bool applied) {
    ev.txs.emplace_back(id, applied);
    if (results_.find(id) != results_.end()) return;
    results_[id] = TxResult{ctx.height, applied};
    results_order_.push_back(id);
    while (results_order_.size() > results_cap_) {
      results_.erase(results_order_.front());
      results_order_.pop_front();
    }
  };

  for (const auto& o : d.mints) record(tx_id(chain_v(), o), apply_mint(o));
  const uint64_t now = d.timestamp;
  for (const auto& o : d.transfers) record(tx_id(chain_v(), o), apply_transfer(o, now));
  for (const auto& o : d.entries) record(tx_id(chain_v(), o), apply_entry(o, now));
  for (const auto& o : d.sudos) record(tx_id(chain_v(), o), apply_sudo(o, ctx, now));
  last_timestamp_ = now;
  mint_rotate_if_full();

  dirty_ = nullptr;
  ev.changed_accounts = std::move(changed);
  // Invariant: nothing past decode_ops in this function may throw -- store_ is mutated with no
  // rollback, so a throw would leave a partial block and diverge. Observers are telemetry; a
  // throwing one is swallowed rather than propagated.
  for (const auto& obs : commit_observers_) {
    try {
      obs(ev);
    } catch (...) {
    }
  }
}

bool App::tx_result(const Hash& id, TxResult& out) const {
  auto it = results_.find(id);
  if (it == results_.end()) return false;
  out = it->second;
  return true;
}

wire::Bytes App::snapshot() const {
  wire::Bytes out;
  wire::Writer w(out);
  const wire::Bytes sc = store_.canonical();
  w.bytes(wire::View(sc.data(), sc.size()));
  put_hash(w, mint_key_);
  put_hash(w, mint_acc_);
  w.u64(mint_fill_);
  w.u64(last_timestamp_);
  w.u64(sudo_minted_);
  std::vector<const Hash*> seen;
  seen.reserve(mint_seen_.size());
  for (const auto& s : mint_seen_) seen.push_back(&s);
  std::sort(seen.begin(), seen.end(), [](const Hash* a, const Hash* b) { return *a < *b; });
  w.count(seen.size());
  for (const Hash* s : seen) put_hash(w, *s);
  return out;
}

void App::restore(wire::View bytes) {
  // Atomic: decode before any mutation; a malformed snapshot throws and leaves state unchanged.
  wire::Reader r(bytes);
  wire::View sc = r.bytes();
  Hash nk = get_hash(r);
  Hash na = get_hash(r);
  uint64_t nf = r.u64();
  uint64_t nts = r.u64();
  uint64_t nsm = r.u64();
  decltype(mint_seen_) next_seen;
  size_t ns = r.count();
  for (size_t i = 0; i < ns; ++i) next_seen.insert(get_hash(r));
  if (!r.empty()) throw wire::Error("services: snapshot has trailing bytes");
  store_.restore(sc);
  mint_key_ = nk;
  mint_acc_ = na;
  mint_fill_ = nf;
  last_timestamp_ = nts;
  sudo_minted_ = nsm;
  mint_seen_ = std::move(next_seen);
}

} // namespace hyle::services
