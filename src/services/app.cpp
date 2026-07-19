#include <hyle/services/app.h>

#include <hyle/services/kv/ops.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <vector>

namespace hyle::services {

using kv::Op;

namespace {
uint64_t sat_add(uint64_t a, uint64_t b) { return a > UINT64_MAX - b ? UINT64_MAX : a + b; }
uint64_t sat_mul(uint64_t a, uint64_t b) {
  if (a == 0 || b == 0) return 0;
  return a > UINT64_MAX / b ? UINT64_MAX : a * b;
}
} // namespace

App::App(Config cfg, std::string chain_id, std::size_t mempool_capacity)
    : cfg_(cfg),
      chain_id_(std::move(chain_id)),
      mempool_(cfg, mempool_capacity, chain_id_) {
  now_fn_ = [] {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
  };
}

App App::from_genesis(const Genesis& g, std::size_t mempool_capacity) {
  App a(g.config, g.chain_id, mempool_capacity);
  for (const auto& alloc : g.allocations) a.seed_account(alloc.first, alloc.second);
  return a;
}

void App::seed_account(const PubKey& k, uint64_t balance) {
  Account acc = load_account(k);
  acc.balance = balance;
  store_account(k, acc);
}

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

bool App::valid_transfer_shape(const TransferOp& o) {
  return valid_transfer_dest(wire::View(o.to.data(), o.to.size()));
}

// True if max_state_bytes is set, the store is at/over it, and `to` names a cell that does not yet
// exist -- i.e. admitting `to` would grow the state past a full cap.
bool App::at_state_cap_for_new_dest(wire::View to) const {
  if (cfg_.max_state_bytes == 0 || store_.bytes() < cfg_.max_state_bytes) return false;
  if (to.empty()) return false;
  if (to[0] == ACCOUNT_PREFIX) {
    if (to.size() != 33) return false;
    PubKey dest{};
    std::memcpy(dest.data(), to.data() + 1, 32);
    return !account_exists(dest);
  }
  if (to[0] == ENTRY_PREFIX)
    return !entry_exists(wire::View(to.data() + 1, to.size() - 1));
  return false;
}

bool App::apply_transfer(const TransferOp& o, uint64_t now) {
  if (!valid_transfer_shape(o)) return false;
  const wire::Bytes sb = xfer_sign_bytes(chain_v(), o.from, wire::View(o.to.data(), o.to.size()), o.amount, o.seq, o.max);
  if (!verify(o.from, wire::View(sb.data(), sb.size()), o.sig)) return false;
  if (!account_exists(o.from)) return false;
  Account from = load_account(o.from);
  if (o.seq != from.sequence) return false;
  // A full chain admits no new cells: reject a transfer whose destination account/entry does not
  // yet exist. Checked before any mutation, so a rejected transfer moves nothing.
  if (at_state_cap_for_new_dest(wire::View(o.to.data(), o.to.size()))) return false;
  uint64_t amount = o.amount;
  uint64_t cost = sat_add(amount, cfg_.fee_transfer);
  if (from.balance < cost) {
    if (!o.max) return false;
    // pay the fee if affordable, send whatever remains
    const uint64_t fee = from.balance < cfg_.fee_transfer ? from.balance : cfg_.fee_transfer;
    amount = from.balance - fee;
    cost = from.balance;
  }
  from.balance -= cost;
  from.sequence++;
  store_account(o.from, from);

  credit_dest(wire::View(o.to.data(), o.to.size()), amount, now, o.from);
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
      // Creating a new entry is new state: refuse it when the store is at the cap.
      if (cfg_.max_state_bytes != 0 && store_.bytes() >= cfg_.max_state_bytes) return false;
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

void App::apply_autofill(const std::vector<PubKey>& members) {
  const uint64_t ceiling = cfg_.credit_autofill_ceiling;
  if (ceiling == 0) return;
  uint64_t maxbal = 0;
  for (const auto& v : members) {
    const uint64_t b = balance(v);
    if (b > maxbal) maxbal = b;
  }
  const uint64_t lift = maxbal >= ceiling ? 0 : ceiling - maxbal;
  const uint64_t bump = sat_add(lift, cfg_.refill_rate);
  if (bump == 0) return;
  for (const auto& v : members) {
    Account a = load_account(v);
    if (a.balance >= ceiling) continue;
    const uint64_t room = ceiling - a.balance;
    const uint64_t grant = bump < room ? bump : room;
    if (grant == 0) continue;
    a.balance += grant;
    store_account(v, a);
  }
}

wire::Bytes App::build_payload(uint64_t) {
  {
    static constexpr size_t kBlockOpCap = 4096;
    Decoded md = mempool_.drain(kBlockOpCap);
    for (auto& t : md.transfers) pending_.transfers.push_back(std::move(t));
    for (auto& e : md.entries) pending_.entries.push_back(std::move(e));
    for (auto& s : md.sudos) pending_.sudos.push_back(std::move(s));
  }
  Decoded d;
  d.timestamp = now_fn_();
  for (const auto& o : pending_.transfers) {
    if (!valid_transfer_shape(o)) continue;
    const wire::Bytes sb = xfer_sign_bytes(chain_v(), o.from, wire::View(o.to.data(), o.to.size()), o.amount, o.seq, o.max);
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
    for (const auto& o : d.transfers) {
      if (!valid_transfer_shape(o)) return false;
      const wire::Bytes sb =
          xfer_sign_bytes(chain_v(), o.from, wire::View(o.to.data(), o.to.size()), o.amount, o.seq, o.max);
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

  const uint64_t now = d.timestamp;
  for (const auto& o : d.transfers) record(tx_id(chain_v(), o), apply_transfer(o, now));
  for (const auto& o : d.entries) record(tx_id(chain_v(), o), apply_entry(o, now));
  for (const auto& o : d.sudos) record(tx_id(chain_v(), o), apply_sudo(o, ctx, now));
  last_timestamp_ = now;
  apply_autofill(ctx.members);

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
  w.u64(last_timestamp_);
  w.u64(sudo_minted_);
  return out;
}

void App::restore(wire::View bytes) {
  // Atomic: decode before any mutation; a malformed snapshot throws and leaves state unchanged.
  wire::Reader r(bytes);
  wire::View sc = r.bytes();
  uint64_t nts = r.u64();
  uint64_t nsm = r.u64();
  if (!r.empty()) throw wire::Error("services: snapshot has trailing bytes");
  store_.restore(sc);
  last_timestamp_ = nts;
  sudo_minted_ = nsm;
}

} // namespace hyle::services
