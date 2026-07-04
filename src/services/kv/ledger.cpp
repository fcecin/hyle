#include <hyle/services/kv/ledger.h>

#include <hyle/core/blog.h>

#include <algorithm>
#include <cstring>

LOG_MODULE_DISABLED("hyle.ledger")

namespace hyle {

namespace {

wire::View v32(const PubKey& k) { return wire::View(k.data(), k.size()); }

bool is_zero(const PubKey& k) {
  return std::all_of(k.begin(), k.end(), [](uint8_t b) { return b == 0; });
}

uint64_t sat_add(uint64_t a, uint64_t b) { return a > UINT64_MAX - b ? UINT64_MAX : a + b; }
uint64_t sat_mul(uint64_t a, uint64_t b) {
  return (a != 0 && b > UINT64_MAX / a) ? UINT64_MAX : a * b;
}

void put_key(wire::Writer& w, const PubKey& k) { w.raw(v32(k)); }
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

const char* name_tag(NameKind k) {
  switch (k) {
    case NameKind::Register: return "HYLE_NAME_REG";
    case NameKind::Update: return "HYLE_NAME_UPD";
    case NameKind::Give: return "HYLE_NAME_GIVE";
    case NameKind::Release: return "HYLE_NAME_REL";
  }
  return "HYLE_NAME_?";
}

struct Decoded {
  std::vector<XferOp> xfers;
  std::vector<EvictOp> evicts;
  std::vector<NameOp> names;
  std::vector<MintOp> mints;
};

Decoded decode_ops(wire::View in) {
  wire::Reader r(in);
  Decoded d;
  size_t nx = r.count();
  for (size_t i = 0; i < nx; ++i) {
    XferOp o;
    o.from = get_key(r);
    o.to = get_key(r);
    o.amount = r.u64();
    o.seq = r.u64();
    std::memcpy(o.sig.data(), r.raw(64).data(), 64);
    d.xfers.push_back(o);
  }
  size_t ne = r.count();
  for (size_t i = 0; i < ne; ++i) {
    EvictOp e;
    e.key = get_key(r);
    e.culler = get_key(r);
    d.evicts.push_back(e);
  }
  size_t nn = r.count();
  for (size_t i = 0; i < nn; ++i) {
    NameOp o;
    const uint8_t nk = r.u8();
    if (nk > static_cast<uint8_t>(NameKind::Release))
      throw wire::Error("name op: kind out of range");
    o.kind = static_cast<NameKind>(nk);
    o.owner = get_key(r);
    wire::View nm = r.bytes();
    o.name.assign(nm.begin(), nm.end());
    o.version = r.u64();
    wire::View dt = r.bytes();
    o.data.assign(dt.begin(), dt.end());
    std::memcpy(o.sig.data(), r.raw(64).data(), 64);
    d.names.push_back(std::move(o));
  }
  size_t nm = r.count();
  for (size_t i = 0; i < nm; ++i) {
    MintOp o;
    o.beneficiary = get_key(r);
    o.nonce = r.u64();
    o.solution = get_hash(r);
    d.mints.push_back(o);
  }
  if (!r.empty()) throw wire::Error("ledger: trailing bytes");
  return d;
}

} // namespace

wire::Bytes Ledger::xfer_sign_bytes(const PubKey& from, const PubKey& to, uint64_t amount,
                                    uint64_t seq) {
  wire::Bytes out;
  wire::Writer w(out);
  w.raw(wire::View(reinterpret_cast<const uint8_t*>("HYLE_XFER_V1"), 12));
  w.raw(v32(from));
  w.raw(v32(to));
  w.u64(amount);
  w.u64(seq);
  return out;
}

wire::Bytes Ledger::name_sign_bytes(NameKind kind, wire::View name, uint64_t version,
                                    wire::View data) {
  const char* tag = name_tag(kind);
  wire::Bytes out;
  wire::Writer w(out);
  w.raw(wire::View(reinterpret_cast<const uint8_t*>(tag), std::strlen(tag)));
  w.bytes(name);
  w.u64(version);
  w.bytes(data);
  return out;
}

XferOp Ledger::make_transfer(const KeyPair& from, const PubKey& to, uint64_t amount, uint64_t seq) {
  XferOp o;
  o.from = from.pub;
  o.to = to;
  o.amount = amount;
  o.seq = seq;
  o.sig = from.sign(xfer_sign_bytes(o.from, o.to, o.amount, o.seq));
  return o;
}
uint64_t Ledger::account_seq(const PubKey& k) const {
  auto it = cells_.find(k);
  return it == cells_.end() ? 0 : it->second.seq;
}

NameOp Ledger::make_register(const KeyPair& owner, wire::View name, wire::View content) {
  NameOp o;
  o.kind = NameKind::Register;
  o.owner = owner.pub;
  o.name.assign(name.begin(), name.end());
  o.version = 1;
  o.data.assign(content.begin(), content.end());
  o.sig = owner.sign(name_sign_bytes(o.kind, name, o.version, content));
  return o;
}

NameOp Ledger::make_update(const KeyPair& owner, wire::View name, uint64_t version,
                           wire::View content) {
  NameOp o;
  o.kind = NameKind::Update;
  o.owner = owner.pub;
  o.name.assign(name.begin(), name.end());
  o.version = version;
  o.data.assign(content.begin(), content.end());
  o.sig = owner.sign(name_sign_bytes(o.kind, name, version, content));
  return o;
}

NameOp Ledger::make_give(const KeyPair& owner, wire::View name, uint64_t version,
                         const PubKey& new_owner) {
  NameOp o;
  o.kind = NameKind::Give;
  o.owner = owner.pub;
  o.name.assign(name.begin(), name.end());
  o.version = version;
  o.data.assign(new_owner.begin(), new_owner.end());
  o.sig = owner.sign(name_sign_bytes(o.kind, name, version, wire::View(o.data)));
  return o;
}

NameOp Ledger::make_release(const KeyPair& owner, wire::View name, uint64_t version) {
  NameOp o;
  o.kind = NameKind::Release;
  o.owner = owner.pub;
  o.name.assign(name.begin(), name.end());
  o.version = version;
  o.sig = owner.sign(name_sign_bytes(o.kind, name, version, wire::View{}));
  return o;
}

uint64_t Ledger::rent_owed(const Cell& c, uint64_t height) const {
  uint64_t elapsed = height > c.last_charged ? height - c.last_charged : 0;
  return sat_mul(sat_mul(rate_, 1 + c.content.size()), elapsed);
}

void Ledger::roll(Cell& c, uint64_t height) const {
  uint64_t owed = rent_owed(c, height);
  c.balance = owed >= c.balance ? 0 : c.balance - owed;
  c.last_charged = height;
}

wire::Bytes Ledger::build_payload(uint64_t) {
  std::vector<const XferOp*> xfers;
  for (const auto& o : pending_xfer_)
    if (verify(o.from, xfer_sign_bytes(o.from, o.to, o.amount, o.seq), o.sig)) xfers.push_back(&o);
  std::vector<const NameOp*> names;
  for (const auto& o : pending_name_)
    if (verify(o.owner, name_sign_bytes(o.kind, wire::View(o.name), o.version, wire::View(o.data)),
               o.sig))
      names.push_back(&o);
  std::vector<const MintOp*> mints;
  if (mint_.enabled && verifier_)
    for (const auto& o : pending_mint_)
      if (pow_difficulty(o.solution) >= mint_.min_diff &&
          verifier_->hash(mint_key_, o.beneficiary, o.nonce) == o.solution)
        mints.push_back(&o);

  wire::Bytes out;
  wire::Writer w(out);
  w.count(xfers.size());
  for (const auto* o : xfers) {
    put_key(w, o->from);
    put_key(w, o->to);
    w.u64(o->amount);
    w.u64(o->seq);
    w.raw(wire::View(o->sig.data(), o->sig.size()));
  }
  w.count(pending_evict_.size());
  for (const auto& e : pending_evict_) {
    put_key(w, e.key);
    put_key(w, e.culler);
  }
  w.count(names.size());
  for (const auto* o : names) {
    w.u8(static_cast<uint8_t>(o->kind));
    put_key(w, o->owner);
    w.bytes(o->name);
    w.u64(o->version);
    w.bytes(o->data);
    w.raw(wire::View(o->sig.data(), o->sig.size()));
  }
  const bool emit_mints = mint_.enabled;
  w.count(emit_mints ? mints.size() : 0);
  if (emit_mints) {
    for (const auto* o : mints) {
      put_key(w, o->beneficiary);
      w.u64(o->nonce);
      put_hash(w, o->solution);
    }
  }
  pending_xfer_.clear();
  pending_evict_.clear();
  pending_name_.clear();
  pending_mint_.clear();
  return out;
}

bool Ledger::validate_payload(wire::View payload) {
  try {
    Decoded d = decode_ops(payload);
    for (const auto& o : d.xfers)
      if (!verify(o.from, xfer_sign_bytes(o.from, o.to, o.amount, o.seq), o.sig)) return false;
    for (const auto& o : d.names)
      if (!verify(o.owner, name_sign_bytes(o.kind, wire::View(o.name), o.version, wire::View(o.data)),
                  o.sig))
        return false;
    if (mint_.enabled && verifier_) {
      for (const auto& o : d.mints) {
        if (pow_difficulty(o.solution) < mint_.min_diff) return false;
        if (!(verifier_->hash(mint_key_, o.beneficiary, o.nonce) == o.solution)) return false;
      }
    }
    return true;
  } catch (const wire::Error&) {
    return false;
  }
}

void Ledger::apply_payload(const ApplyContext& ctx, wire::View payload) {
  const uint64_t h = ctx.height;

  if (!is_zero(ctx.proposer)) {
    Cell& c = cells_[ctx.proposer];
    roll(c, h);
    c.balance = sat_add(c.balance, REWARD);
    LOGTRACE << "block reward " << REWARD << " at height " << h << VAL("proposer", ctx.proposer);
  }

  Decoded d = decode_ops(payload);

  for (const auto& o : d.names) {
    if (!verify(o.owner, name_sign_bytes(o.kind, wire::View(o.name), o.version, wire::View(o.data)),
                o.sig))
      continue;
    PubKey key{};
    Hash k = sha256(wire::View(o.name));
    std::memcpy(key.data(), k.data(), 32);

    if (o.kind == NameKind::Register) {
      if (o.version == 0) continue;
      auto it = cells_.find(key);
      if (it != cells_.end() && it->second.named) continue;
      Cell& c = cells_[key];
      roll(c, h);
      c.named = true;
      c.owner = o.owner;
      c.version = o.version;
      c.content = o.data;
      LOGDEBUG << "name registered (" << o.name.size() << "B name, " << o.data.size()
               << "B content)" << VAL("owner", o.owner);
      continue;
    }
    auto it = cells_.find(key);
    if (it == cells_.end() || !it->second.named) continue;
    if (!(it->second.owner == o.owner)) continue;
    if (o.version <= it->second.version) continue;
    roll(it->second, h);
    if (o.kind == NameKind::Update) {
      it->second.content = o.data;
      it->second.version = o.version;
    } else if (o.kind == NameKind::Give) {
      if (o.data.size() < 32) continue;
      PubKey no{};
      std::memcpy(no.data(), o.data.data(), 32);
      it->second.owner = no;
      it->second.version = o.version;
    } else if (o.kind == NameKind::Release) {
      cells_.erase(it);
    }
    LOGDEBUG << "name op kind " << static_cast<int>(o.kind) << " version " << o.version
             << VAL("owner", o.owner);
  }

  for (const auto& o : d.xfers) {
    if (o.from == o.to || o.amount == 0) continue;
    if (!verify(o.from, xfer_sign_bytes(o.from, o.to, o.amount, o.seq), o.sig)) continue;
    auto it = cells_.find(o.from);
    if (it == cells_.end()) continue;
    if (o.seq != it->second.seq) continue;
    roll(it->second, h);
    if (it->second.balance < o.amount) continue;
    it->second.balance -= o.amount;
    it->second.seq++;
    bool drained = it->second.balance == 0 && !it->second.named && it->second.seq == 0;
    if (drained) cells_.erase(it);
    Cell& to = cells_[o.to];
    roll(to, h);
    to.balance = sat_add(to.balance, o.amount);
    LOGTRACE << "transfer " << o.amount << VAL("from", o.from) << VAL("to", o.to);
  }

  for (const auto& e : d.evicts) {
    auto it = cells_.find(e.key);
    if (it == cells_.end()) continue;
    const uint64_t owed = rent_owed(it->second, h);
    roll(it->second, h);
    if (it->second.balance != 0 || owed == 0) continue;
    cells_.erase(it);
    Cell& culler = cells_[e.culler];
    roll(culler, h);
    culler.balance = sat_add(culler.balance, BOUNTY);
    LOGDEBUG << "evicted starved cell, bounty " << BOUNTY << VAL("culler", e.culler);
  }

  if (mint_.enabled && verifier_) {
    for (const auto& o : d.mints) apply_mint(o, h);
    mint_rotate_if_full();
  }
}

bool Ledger::apply_mint(const MintOp& o, uint64_t height) {
  if (pow_difficulty(o.solution) < mint_.min_diff) {
    LOGTRACE << "mint reject: below floor (" << pow_difficulty(o.solution) << " < "
             << mint_.min_diff << ")";
    return false;
  }
  if (!(verifier_->hash(mint_key_, o.beneficiary, o.nonce) == o.solution)) {
    LOGTRACE << "mint reject: solution does not verify for the current epoch key";
    return false;
  }
  if (!mint_seen_.insert(o.solution).second) {
    LOGTRACE << "mint reject: replay (already accepted this epoch)";
    return false;
  }

  unsigned d = pow_difficulty(o.solution);
  Cell& c = cells_[o.beneficiary];
  roll(c, height);
  c.balance = sat_add(c.balance, mint_reward(d));
  LOGDEBUG << "mint accepted: difficulty " << d << " reward " << mint_reward(d) << " fill "
           << (mint_fill_ + 1) << "/" << mint_.capacity << VAL("beneficiary", o.beneficiary);

  wire::Bytes buf;
  wire::Writer w(buf);
  w.raw(wire::View(mint_acc_.data(), mint_acc_.size()));
  w.raw(wire::View(o.solution.data(), o.solution.size()));
  mint_acc_ = sha256(wire::View(buf));
  ++mint_fill_;
  return true;
}

void Ledger::mint_rotate_if_full() {
  if (mint_fill_ < mint_.capacity) return;
  wire::Bytes buf;
  wire::Writer w(buf);
  w.raw(wire::View(reinterpret_cast<const uint8_t*>("HYLE_POW_ROTATE"), 15));
  w.raw(wire::View(mint_key_.data(), mint_key_.size()));
  w.u64(mint_fill_);
  w.raw(wire::View(mint_acc_.data(), mint_acc_.size()));
  mint_key_ = sha256(wire::View(buf));
  mint_acc_ = mint_key_;
  mint_fill_ = 0;
  mint_seen_.clear();
  LOGINFO << "mint: epoch full at capacity " << mint_.capacity << ", rotated to new key"
          << VAL("epoch_key", mint_key_);
}

uint64_t Ledger::mint_reward(unsigned difficulty) const {
  if (difficulty == 0) return 0;
  unsigned d = difficulty > MINT_REWARD_MAX_DIFF ? MINT_REWARD_MAX_DIFF : difficulty;
  return sat_mul(uint64_t(1) << (d - 1), mint_.reward_base);
}

MintOp Ledger::make_mint(const PowVerifier& v, const Hash& epoch_key, const PubKey& beneficiary,
                         unsigned min_diff, uint64_t start_nonce) {
  MintOp o;
  o.beneficiary = beneficiary;
  for (uint64_t n = start_nonce;; ++n) {
    Hash h = v.hash(epoch_key, beneficiary, n);
    if (pow_difficulty(h) >= min_diff) {
      o.nonce = n;
      o.solution = h;
      return o;
    }
  }
}

wire::Bytes Ledger::snapshot() const {
  std::vector<const PubKey*> keys;
  keys.reserve(cells_.size());
  for (const auto& e : cells_) keys.push_back(&e.first);
  std::sort(keys.begin(), keys.end(), [](const PubKey* a, const PubKey* b) { return *a < *b; });

  wire::Bytes out;
  wire::Writer w(out);
  w.count(keys.size());
  for (const PubKey* k : keys) {
    const Cell& c = cells_.at(*k);
    put_key(w, *k);
    w.u64(c.balance);
    w.u64(c.last_charged);
    w.u64(c.seq);
    w.u8(c.named ? 1 : 0);
    if (c.named) {
      put_key(w, c.owner);
      w.u64(c.version);
      w.bytes(c.content);
    }
  }

  put_hash(w, mint_key_);
  put_hash(w, mint_acc_);
  w.u64(mint_fill_);
  std::vector<const Hash*> seen;
  seen.reserve(mint_seen_.size());
  for (const auto& s : mint_seen_) seen.push_back(&s);
  std::sort(seen.begin(), seen.end(), [](const Hash* a, const Hash* b) { return *a < *b; });
  w.count(seen.size());
  for (const Hash* s : seen) put_hash(w, *s);
  return out;
}

void Ledger::restore(wire::View bytes) {
  // Atomic: commit only on full success; a malformed snapshot leaves state unchanged.
  decltype(cells_) next_cells;
  wire::Reader r(bytes);
  size_t n = r.count();
  for (size_t i = 0; i < n; ++i) {
    PubKey k = get_key(r);
    Cell c;
    c.balance = r.u64();
    c.last_charged = r.u64();
    c.seq = r.u64();
    c.named = r.u8() != 0;
    if (c.named) {
      c.owner = get_key(r);
      c.version = r.u64();
      wire::View ct = r.bytes();
      c.content.assign(ct.begin(), ct.end());
    }
    next_cells[k] = std::move(c);
  }

  Hash next_key = get_hash(r);
  Hash next_acc = get_hash(r);
  uint64_t next_fill = r.u64();
  decltype(mint_seen_) next_seen;
  size_t ns = r.count();
  for (size_t i = 0; i < ns; ++i) next_seen.insert(get_hash(r));
  if (!r.empty()) throw wire::Error("ledger: trailing bytes after snapshot");

  cells_ = std::move(next_cells);
  mint_key_ = next_key;
  mint_acc_ = next_acc;
  mint_fill_ = next_fill;
  mint_seen_ = std::move(next_seen);
}

uint64_t Ledger::balance(const PubKey& k) const {
  auto it = cells_.find(k);
  return it == cells_.end() ? 0 : it->second.balance;
}

uint64_t Ledger::total() const {
  uint64_t t = 0;
  for (const auto& e : cells_) t += e.second.balance;
  return t;
}

const Ledger::Cell* Ledger::find_named(wire::View name) const {
  Hash k = sha256(name);
  PubKey key{};
  std::memcpy(key.data(), k.data(), 32);
  auto it = cells_.find(key);
  if (it == cells_.end() || !it->second.named) return nullptr;
  return &it->second;
}

bool Ledger::has_name(wire::View name) const { return find_named(name) != nullptr; }

PubKey Ledger::name_owner(wire::View name) const {
  const Cell* c = find_named(name);
  return c ? c->owner : PubKey{};
}

uint64_t Ledger::name_version(wire::View name) const {
  const Cell* c = find_named(name);
  return c ? c->version : 0;
}

wire::Bytes Ledger::name_content(wire::View name) const {
  const Cell* c = find_named(name);
  return c ? c->content : wire::Bytes{};
}

} // namespace hyle
