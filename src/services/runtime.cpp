#include <hyle/services/runtime.h>

#include <hyle/core/blog.h>
#include <hyle/services/hex.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <thread>

LOG_MODULE("hyle.runtime")

namespace hyle::services {

// Catch-up limits. Responses are sized to the transport's max_message (always at least one
// block, so progress never wedges on the budget); snapshot candidates and their pooled
// attestations are capped against garbage floods.
static constexpr size_t kSyncRespBudget = 1u << 20;
static constexpr size_t kSyncCandCap = 8;
static constexpr size_t kSyncAttCap = 64;
static constexpr unsigned kSyncBroadcastAfter = 3;  // stalled retries before broadcasting requests
static constexpr unsigned kSyncResetAfter = 8;      // stalled retries before re-detecting from scratch

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

hyle::NodeConfig Runtime::make_node_cfg(const Genesis& g, const NodeOptions& opts) {
  hyle::NodeConfig cfg;
  // Consensus rules come from the genesis (all nodes agree); operational params from opts.
  cfg.chain_id = g.chain_id;
  cfg.member_cap = g.config.member_cap;
  cfg.member_floor = g.config.member_floor;
  cfg.max_value_bytes = g.config.max_value_bytes;
  cfg.block_retention = opts.block_retention;
  cfg.snapshot_interval = opts.snapshot_interval;
  cfg.data_dir = opts.data_dir;
  return cfg;
}

Runtime::Runtime(const Genesis& g, const KeyPair& key, NodeOptions opts, Transport* net)
    : key_(key),
      app_(App::from_genesis(g, opts.mempool_capacity)),
      vset_(make_vset(g)),
      node_(key, vset_, app_, make_node_cfg(g, opts)),
      engine_(std::make_unique<malachite::Engine>(make_engine_cfg(key, 1, vset_), node_)),
      net_(net),
      pace_ms_(opts.block_pace_ms),
      evidence_dir_(opts.evidence_dir),
      sync_retry_ms_(opts.sync_retry_ms) {
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
  if (d.transfers.empty() && d.entries.empty() && d.sudos.empty()) return;
  wire::Bytes tx = encode_ops(d);
  net_->broadcast(MsgType::Tx, Channel::Mempool, wire::View(tx.data(), tx.size()));
}

// ---- catch-up ----
// A node behind the observed head pulls the retained blocks it lacks from a peer and replays
// them under certificate verification; a node behind every peer's retained window first pulls
// the stored snapshot, adopted on a >2/3 attestation quorum, then the block tail. Both ends
// live here, so any Transport (TCP mesh, CES peer mesh) carries them unchanged.

void Runtime::send_blocks_req() {
  SyncBlocksReq req;
  req.from = node_.applied_height();
  req.nonce = ++sync_nonce_;  // varies retries past transport dedup caches
  wire::Bytes out = encode_sync_blocks_req(req);
  const wire::View v(out.data(), out.size());
  if (have_sync_peer_)
    net_->send(sync_peer_, MsgType::ValueReq, Channel::Bulk, v);
  else
    net_->broadcast(MsgType::ValueReq, Channel::Bulk, v);
}

void Runtime::send_snap_req() {
  SyncSnapReq req;
  req.have = node_.applied_height();
  req.nonce = ++sync_nonce_;
  wire::Bytes out = encode_sync_snap_req(req);
  // broadcast: adoption needs attestations pooled from a quorum of peers
  net_->broadcast(MsgType::SnapReq, Channel::Bulk, wire::View(out.data(), out.size()));
}

void Runtime::request_sync() { maybe_sync(); }

void Runtime::maybe_sync() {
  if (!net_) return;
  // A decide the value never arrived for is behind-ness evidence with no Prop attached.
  if (node_.last_decided() > observed_head_) observed_head_ = node_.last_decided();
  const uint64_t applied = node_.applied_height();
  if (observed_head_ <= applied) {
    want_snapshot_ = false;
    if (!snap_cand_.empty()) snap_cand_.clear();
    sync_stalls_ = 0;
    return;
  }
  const auto now = std::chrono::steady_clock::now();
  const bool first = last_sync_req_.time_since_epoch().count() == 0;
  if (!first && now - last_sync_req_ < std::chrono::milliseconds(sync_retry_ms_)) return;
  if (!first && applied == last_sync_applied_) {
    ++sync_stalls_;
    if (sync_stalls_ >= kSyncBroadcastAfter) have_sync_peer_ = false;
    if (sync_stalls_ >= kSyncResetAfter) {
      // nobody could help from here; drop the stale signal and re-detect from live traffic
      observed_head_ = applied;
      want_snapshot_ = false;
      snap_cand_.clear();
      sync_stalls_ = 0;
      return;
    }
  } else {
    sync_stalls_ = 0;
  }
  last_sync_applied_ = applied;
  last_sync_req_ = now;
  if (want_snapshot_) {
    snap_cand_.clear();  // stale candidates would pin heights the peers have moved past
    send_snap_req();
  } else {
    send_blocks_req();  // last: an inline transport can recurse into on_message
  }
}

void Runtime::serve_blocks(const PubKey& src, wire::View payload) {
  if (!net_) return;
  SyncBlocksReq req;
  try {
    req = decode_sync_blocks_req(payload);
  } catch (const wire::Error&) {
    return;
  }
  const uint64_t head = node_.applied_height();
  if (req.from >= head) return;
  size_t budget = kSyncRespBudget;
  const size_t cap = net_->max_message();
  if (cap != SIZE_MAX) budget = std::min(budget, cap > 4096 ? cap - 4096 : cap);
  SyncBlocksResp resp;
  resp.nonce = req.nonce;
  resp.head = head;
  size_t bytes = 0;
  for (uint64_t h = req.from + 1; h <= head; ++h) {
    const hyle::Block* b = node_.block_at(h);
    if (!b) break;  // pruned or gapped past here; an empty resp tells them to fetch a snapshot
    const size_t sz = 48 + b->value.size() + b->certificate.size();
    if (!resp.blocks.empty() && bytes + sz > budget) break;
    SyncBlock sb;
    sb.height = h;
    sb.proposer = b->proposer;
    sb.value = b->value;
    sb.certificate = b->certificate;
    resp.blocks.push_back(std::move(sb));
    bytes += sz;
  }
  wire::Bytes out = encode_sync_blocks_resp(resp);
  if (out.size() > cap)
    LOGWARNING << "sync: response for height " << (req.from + 1) << " (" << out.size()
               << "B) exceeds the transport max message (" << cap << "B); it will not arrive";
  net_->send(src, MsgType::ValueResp, Channel::Bulk, wire::View(out.data(), out.size()));
}

void Runtime::serve_snapshot(const PubKey& src, wire::View payload) {
  if (!net_) return;
  SyncSnapReq req;
  try {
    req = decode_sync_snap_req(payload);
  } catch (const wire::Error&) {
    return;
  }
  if (!node_.has_snapshot() || node_.snapshot_height() <= req.have) return;
  SyncSnapResp resp;
  resp.nonce = req.nonce;
  resp.snap = node_.stored_snapshot();
  wire::Bytes out = encode_sync_snap_resp(resp);
  if (out.size() > net_->max_message()) {
    LOGWARNING << "sync: snapshot at height " << resp.snap.height << " (" << out.size()
               << "B) exceeds the transport max message; joiners cannot sync until state fits";
    return;
  }
  net_->send(src, MsgType::SnapResp, Channel::Bulk, wire::View(out.data(), out.size()));
}

bool Runtime::replay_blocks(const std::vector<SyncBlock>& blocks) {
  const uint64_t start = node_.applied_height() + 1;
  // Replay probes a fresh engine that becomes the live engine only once the first certificate
  // verifies, so a forged response never disturbs an in-flight healthy round.
  auto cand = std::make_unique<malachite::Engine>(
      make_engine_cfg(key_, start, node_.validators_for(start)), node_);
  bool adopted = false;
  for (const auto& b : blocks) {
    if (b.height != node_.applied_height() + 1) break;  // strictly in order
    node_.clear_sync();
    cand->start_height(b.height, node_.validators_for(b.height));
    cand->sync_value_response(malachite::BytesView(b.proposer.data(), b.proposer.size()),
                              malachite::BytesView(b.value.data(), b.value.size()),
                              malachite::BytesView(b.certificate.data(), b.certificate.size()));
    if (!node_.got_sync()) break;  // certificate rejected
    if (!adopted) {
      node_.clear_proposal();  // any pending proposal is for a stale height
      adopted = true;
    }
    cand->proposed_value(node_.sync_height(), node_.sync_round(), malachite::Round::nil(),
                         malachite::BytesView(b.proposer.data(), b.proposer.size()),
                         malachite::BytesView(b.value.data(), b.value.size()), true,
                         malachite::ValueOrigin::Sync);
    node_.clear_sync();
    if (node_.applied_height() != b.height) break;  // parent mismatch: keep what applied
  }
  if (!adopted) return false;
  engine_ = std::move(cand);
  // Resume the live cursors at the new head so the next advance()/run_to starts head+1.
  started_ = node_.applied_height();
  if (target_ != 0 && target_ < started_) target_ = started_;
  LOGINFO << "sync: replayed to height " << node_.applied_height();
  return true;
}

void Runtime::handle_blocks_resp(const PubKey& src, wire::View payload) {
  if (!net_) return;
  SyncBlocksResp resp;
  try {
    resp = decode_sync_blocks_resp(payload);
  } catch (const wire::Error&) {
    return;
  }
  if (resp.head > observed_head_) observed_head_ = resp.head;
  const uint64_t applied = node_.applied_height();
  if (resp.head > applied) {
    sync_peer_ = src;
    have_sync_peer_ = true;
  }
  if (resp.blocks.empty()) {
    // a peer ahead of us with no servable tail: the window is pruned, fetch a snapshot
    if (resp.head > applied) want_snapshot_ = true;
    return;
  }
  if (resp.blocks.front().height != applied + 1) return;  // stale or unusable
  if (!replay_blocks(resp.blocks)) return;
  want_snapshot_ = false;
  sync_stalls_ = 0;
  if (observed_head_ > node_.applied_height()) {
    last_sync_req_ = std::chrono::steady_clock::now();
    last_sync_applied_ = node_.applied_height();
    send_blocks_req();  // last: an inline transport can recurse into on_message
  }
}

void Runtime::handle_snap_resp(wire::View payload) {
  if (!net_ || !want_snapshot_) return;  // no transport, or unsolicited
  SyncSnapResp resp;
  try {
    resp = decode_sync_snap_resp(payload);
  } catch (const wire::Error&) {
    return;
  }
  const uint64_t applied = node_.applied_height();
  if (resp.snap.height <= applied) return;
  const Hash key = snapshot_content_key(resp.snap);
  auto it = snap_cand_.find(key);
  if (it == snap_cand_.end()) {
    if (snap_cand_.size() >= kSyncCandCap) return;
    it = snap_cand_.emplace(key, std::move(resp.snap)).first;
    if (it->second.attestations.size() > kSyncAttCap) it->second.attestations.resize(kSyncAttCap);
  } else {
    for (const auto& a : resp.snap.attestations) {
      if (it->second.attestations.size() >= kSyncAttCap) break;
      bool dup = false;
      for (const auto& e : it->second.attestations)
        if (e.signer == a.signer) { dup = true; break; }
      if (!dup) it->second.attestations.push_back(a);
    }
  }
  // The trusted set is this node's best knowledge (genesis for a fresh joiner): the weak
  // subjectivity checkpoint every BFT joiner needs. Attempt adoption only once a quorum of
  // pooled attestations is even possible; adopt_snapshot verifies signatures and power.
  const malachite::ValidatorSet trusted = node_.validators_for(applied + 1);
  if (it->second.attestations.size() * 3 <= trusted.size() * 2) return;
  if (!node_.adopt_snapshot(it->second, trusted)) return;
  const uint64_t h = node_.applied_height();
  engine_ = std::make_unique<malachite::Engine>(
      make_engine_cfg(key_, h + 1, node_.validators_for(h + 1)), node_);
  node_.clear_proposal();
  node_.clear_sync();
  started_ = h;
  if (target_ != 0 && target_ < h) target_ = h;
  snap_cand_.clear();
  want_snapshot_ = false;
  sync_stalls_ = 0;
  LOGINFO << "sync: adopted snapshot at height " << h;
  if (observed_head_ > h) {
    last_sync_req_ = std::chrono::steady_clock::now();
    last_sync_applied_ = h;
    send_blocks_req();  // fetch the tail; last: an inline transport can recurse
  }
}

void Runtime::on_message(const PubKey& src, MsgType type, wire::View payload) {
  if (type == MsgType::Consensus) {
    engine_->recv(malachite::BytesView(payload.data(), payload.size()));
    return;
  }
  if (type == MsgType::ValueReq) {
    serve_blocks(src, payload);
    return;
  }
  if (type == MsgType::ValueResp) {
    handle_blocks_resp(src, payload);
    return;
  }
  if (type == MsgType::SnapReq) {
    serve_snapshot(src, payload);
    return;
  }
  if (type == MsgType::SnapResp) {
    handle_snap_resp(payload);
    return;
  }
  if (type == MsgType::Tx) {
    bool fresh = false;
    try {
      Decoded d = decode_ops(payload);
      for (const auto& t : d.transfers) if (app_.admit_transfer(t) == Admit::Ok) fresh = true;
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

    // A verified Prop at h evidences a chain at h-1: the behind detector and the peer to ask.
    if (h > 0) {
      if (h - 1 > observed_head_) observed_head_ = h - 1;
      if (h > node_.applied_height() + 1) {
        sync_peer_ = src;
        have_sync_peer_ = true;
      }
    }

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
  maybe_sync();  // last: an inline transport can recurse into on_message
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
