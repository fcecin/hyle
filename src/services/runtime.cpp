#include <hyle/services/runtime.h>

#include <hyle/core/blog.h>
#include <hyle/services/hex.h>

#include <chrono>
#include <fstream>
#include <thread>

LOG_MODULE("hyle.runtime")

namespace hyle::services {

malachite::ValidatorSet Runtime::make_vset(const Genesis& g) {
  malachite::ValidatorSet vs;
  for (const auto& pk : g.validators) {
    malachite::Validator v;
    v.address = malachite::Bytes(pk.begin(), pk.end());
    v.public_key = v.address;
    v.voting_power = 1;
    vs.push_back(v);
  }
  return vs;
}

malachite::Config Runtime::make_engine_cfg(const KeyPair& key, uint64_t h,
                                           const malachite::ValidatorSet& vs) {
  malachite::Config cfg;
  cfg.address = malachite::Bytes(key.pub.begin(), key.pub.end());
  cfg.initial_height = h;
  cfg.initial_validator_set = vs;
  cfg.value_payload = malachite::ValuePayload::PartsOnly;
  return cfg;
}

hyle::NodeConfig Runtime::make_node_cfg(const Genesis& g) {
  hyle::NodeConfig cfg;
  cfg.chain_id = g.chain_id;
  return cfg;
}

Runtime::Runtime(const Genesis& g, const KeyPair& key, uint64_t block_pace_ms, Transport* net)
    : key_(key),
      app_(App::from_genesis(g)),
      vset_(make_vset(g)),
      node_(key, vset_, app_, make_node_cfg(g)),
      engine_(std::make_unique<malachite::Engine>(make_engine_cfg(key, 1, vset_), node_)),
      net_(net),
      pace_ms_(block_pace_ms) {
  if (net_)
    net_->on_recv = [this](const PubKey& src, MsgType type, wire::View payload) {
      on_message(src, type, payload);
    };
}

// tag || height || round || sha256(value).
static wire::Bytes prop_sign_bytes(wire::View chain_id, malachite::Height h, int64_t round,
                                   wire::View value) {
  wire::Bytes out;
  wire::Writer w(out);
  w.str("MORPHE_PROP_V1");
  w.bytes(chain_id);
  w.u64(h);
  w.u64(static_cast<uint64_t>(round));
  const Hash vh = sha256(value);
  w.raw(wire::View(vh.data(), vh.size()));
  return out;
}

// [u64 height][u64 round][proposer:32][bytes value][sig:64].
static wire::Bytes encode_prop(wire::View chain_id, malachite::Height h, malachite::Round r,
                               const KeyPair& key, malachite::BytesView value) {
  const wire::View vv(value.data, value.size);
  const wire::Bytes sb = prop_sign_bytes(chain_id, h, r.value, vv);
  const Sig sig = key.sign(wire::View(sb.data(), sb.size()));
  wire::Bytes out;
  wire::Writer w(out);
  w.u64(h);
  w.u64(static_cast<uint64_t>(r.value));
  w.raw(wire::View(key.pub.data(), key.pub.size()));
  w.bytes(vv);
  w.raw(wire::View(sig.data(), sig.size()));
  return out;
}

static wire::Bytes encode_tx_transfer(const TransferOp& op) {
  Decoded d;
  d.transfers.push_back(op);
  return encode_ops(d);
}
static wire::Bytes encode_tx_mint(const MintOp& op) {
  Decoded d;
  d.mints.push_back(op);
  return encode_ops(d);
}
static wire::Bytes encode_tx_entry(const EntryOp& op) {
  Decoded d;
  d.entries.push_back(op);
  return encode_ops(d);
}
static wire::Bytes encode_tx_sudo(const SudoOp& op) {
  Decoded d;
  d.sudos.push_back(op);
  return encode_ops(d);
}

Admit Runtime::submit(const TransferOp& op) {
  Admit a = app_.admit_transfer(op);
  if (a == Admit::Ok && net_) {
    wire::Bytes tx = encode_tx_transfer(op);
    net_->broadcast(MsgType::Tx, Channel::Mempool, wire::View(tx.data(), tx.size()));
  }
  return a;
}
Admit Runtime::submit(const MintOp& op) {
  Admit a = app_.admit_mint(op);
  if (a == Admit::Ok && net_) {
    wire::Bytes tx = encode_tx_mint(op);
    net_->broadcast(MsgType::Tx, Channel::Mempool, wire::View(tx.data(), tx.size()));
  }
  return a;
}
Admit Runtime::submit(const EntryOp& op) {
  Admit a = app_.admit_entry(op);
  if (a == Admit::Ok && net_) {
    wire::Bytes tx = encode_tx_entry(op);
    net_->broadcast(MsgType::Tx, Channel::Mempool, wire::View(tx.data(), tx.size()));
  }
  return a;
}
Admit Runtime::submit(const SudoOp& op) {
  Admit a = app_.admit_sudo(op);
  if (a == Admit::Ok && net_) {
    wire::Bytes tx = encode_tx_sudo(op);
    net_->broadcast(MsgType::Tx, Channel::Mempool, wire::View(tx.data(), tx.size()));
  }
  return a;
}

void Runtime::regossip() {
  if (!net_) return;
  Decoded d = app_.mempool().snapshot();
  if (d.mints.empty() && d.transfers.empty() && d.entries.empty() && d.sudos.empty()) return;
  wire::Bytes tx = encode_ops(d);
  net_->broadcast(MsgType::Tx, Channel::Mempool, wire::View(tx.data(), tx.size()));
}

void Runtime::on_message(const PubKey&, MsgType type, wire::View payload) {
  if (type == MsgType::Consensus) {
    engine_->recv(malachite::BytesView(payload.data(), payload.size()));
    return;
  }
  if (type == MsgType::Tx) {
    bool fresh = false;
    try {
      Decoded d = decode_ops(payload);
      for (const auto& t : d.transfers) if (app_.admit_transfer(t) == Admit::Ok) fresh = true;
      for (const auto& m : d.mints) if (app_.admit_mint(m) == Admit::Ok) fresh = true;
      for (const auto& e : d.entries) if (app_.admit_entry(e) == Admit::Ok) fresh = true;
      for (const auto& s : d.sudos) if (app_.admit_sudo(s) == Admit::Ok) fresh = true;
    } catch (const wire::Error&) {
      return;
    }
    if (fresh && net_) net_->broadcast(MsgType::Tx, Channel::Mempool, payload);
    return;
  }
  if (type == MsgType::Prop) {
    malachite::Height h;
    malachite::Round r{0};
    PubKey proposer{};
    wire::Bytes value;
    Sig sig{};
    try {
      wire::Reader rd(payload);
      h = rd.u64();
      r = malachite::Round{static_cast<int64_t>(rd.u64())};
      wire::View prop = rd.raw(32);
      std::copy(prop.begin(), prop.end(), proposer.begin());
      wire::View val = rd.bytes();
      value.assign(val.begin(), val.end());
      wire::View s = rd.raw(64);
      std::copy(s.begin(), s.end(), sig.begin());
      if (!rd.empty()) return;
    } catch (const wire::Error&) {
      return;
    }

    {
      const malachite::ValidatorSet vs = node_.validators_for(h == 0 ? 1 : h);
      bool is_val = false;
      for (const auto& v : vs)
        if (v.public_key.size() == proposer.size() &&
            std::equal(proposer.begin(), proposer.end(), v.public_key.begin())) { is_val = true; break; }
      if (!is_val) return;
    }

    const wire::Bytes sb = prop_sign_bytes(chain_v(), h, r.value, wire::View(value.data(), value.size()));
    if (!verify(proposer, wire::View(sb.data(), sb.size()), sig)) return;

    const uint64_t tip = node_.applied_height();
    if (h + 1 >= tip && h <= tip + kEvidenceLookahead) {
      const Hash vh = sha256(wire::View(value.data(), value.size()));
      std::string rk = std::to_string(r.value);
      rk.append(reinterpret_cast<const char*>(proposer.data()), proposer.size());
      auto& bucket = proposal_seen_[h];
      auto it = bucket.find(rk);
      if (it != bucket.end()) {
        if (!(it->second == vh)) record_evidence(h, r.value, proposer, it->second, vh);
      } else if (bucket.size() < kMaxEvidencePerHeight) {
        bucket.emplace(std::move(rk), vh);
      }
      while (!proposal_seen_.empty() && proposal_seen_.begin()->first + 1 < tip)
        proposal_seen_.erase(proposal_seen_.begin());
    }

    bool ok = node_.accept_proposed(malachite::BytesView(value.data(), value.size()));
    engine_->proposed_value(h, r, malachite::Round::nil(),
                            malachite::BytesView(proposer.data(), proposer.size()),
                            malachite::BytesView(value.data(), value.size()), ok,
                            malachite::ValueOrigin::Consensus);
  }
}

bool Runtime::pump() {
  bool progress = false;
  if (node_.wants_propose()) {
    const malachite::Height h = node_.proposal_height();
    const malachite::Round r = node_.proposal_round();
    const malachite::Bytes val = node_.proposal_value().to_owned();
    node_.clear_proposal();
    engine_->propose(h, r, malachite::BytesView(val));
    if (net_) {
      wire::Bytes p = encode_prop(chain_v(), h, r, key_, malachite::BytesView(val));
      net_->broadcast(MsgType::Prop, Channel::Consensus, wire::View(p.data(), p.size()));
    }
    progress = true;
  }
  for (auto& m : node_.drain_outbox()) {
    if (net_) net_->broadcast(MsgType::Consensus, Channel::Consensus, wire::View(m.data(), m.size()));
    progress = true;
  }
  return progress;
}

bool Runtime::fire_one_timeout() {
  const auto& ts = node_.timers();
  if (ts.empty()) return false;
  size_t bi = 0;
  uint64_t best = UINT64_MAX;
  for (size_t k = 0; k < ts.size(); ++k)
    if (ts[k].dur < best) { best = ts[k].dur; bi = k; }
  const hyle::Timer t = node_.take_timer(bi);
  engine_->timeout_elapsed(malachite::Timeout{t.kind, malachite::Round{t.round}});
  return true;
}

void Runtime::vote_add(const PubKey& target) {
  node_.submit_gov_vote(consensus::Governance::Kind::Add, target);
}
void Runtime::vote_remove(const PubKey& target) {
  node_.submit_gov_vote(consensus::Governance::Kind::Remove, target);
}

void Runtime::record_evidence(uint64_t height, int64_t round, const PubKey& proposer, const Hash& a,
                              const Hash& b) {
  ++evidence_count_;
  if (evidence_dir_.empty()) return;
  const std::string pk = hex_encode(proposer.data(), proposer.size());
  const std::string path =
      evidence_dir_ + "/evidence-" + std::to_string(height) + "-" + std::to_string(round) + "-" + pk +
      ".txt";
  std::ofstream f(path, std::ios::trunc);
  if (!f) return;
  f << "MORPHE EVIDENCE double-sign\n";
  f << "members " << node_.member_count() << "\n";
  f << "height " << height << "\n";
  f << "round " << round << "\n";
  f << "proposer " << pk << "\n";
  f << "value_a " << hex_encode(a.data(), a.size()) << "\n";
  f << "value_b " << hex_encode(b.data(), b.size()) << "\n";
}

void Runtime::begin() {
  if (started_ != 0) return;
  started_ = 1;
  engine_->start_height(1, node_.validators_for(1));
}

bool Runtime::advance() {
  bool advanced = false;
  while (node_.last_decided() >= started_) {
    ++started_;
    engine_->start_height(started_, node_.validators_for(started_));
    advanced = true;
  }
  return advanced;
}

void Runtime::run_to(uint64_t goal) {
  if (target_ == 0) {
    target_ = 1;
    engine_->start_height(1, node_.validators_for(1));
  }
  constexpr int kMaxTicks = 200000;
  int tick = 0;
  for (; tick < kMaxTicks && node_.applied_height() < goal; ++tick) {
    const bool progress = pump();
    if (node_.applied_height() >= target_) {
      ++target_;
      engine_->start_height(target_, node_.validators_for(target_));
      continue;
    }
    if (!progress && !fire_one_timeout()) return;
  }
  if (tick >= kMaxTicks && node_.applied_height() < goal)
    LOGWARNING << "run_to hit the " << kMaxTicks << "-tick cap at height " << node_.applied_height()
               << " (goal " << goal << "): consensus did not advance this call";
}

void Runtime::run() {
  uint64_t h = 1;
  while (!stop_) {
    run_to(h);
    std::this_thread::sleep_for(std::chrono::milliseconds(pace_ms_));
    ++h;
  }
}

} // namespace hyle::services
