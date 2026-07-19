#include <hyle/core/node.h>

#include <hyle/core/blog.h>

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <set>
#include <stdexcept>
#include <string>

LOG_MODULE_DISABLED("hyle.node")

namespace hyle {

namespace {

wire::View wv(malachite::BytesView b) { return wire::View(b.data, b.size); }

// Vote WAL record: [u32 big-endian length][length bytes].
// each fsync'd before its vote is broadcast, so a torn tail is a vote never sent: no double-sign
std::string pubkey_hex(const PubKey& k) {
  static const char* d = "0123456789abcdef";
  std::string s;
  s.reserve(64);
  for (uint8_t b : k) {
    s.push_back(d[b >> 4]);
    s.push_back(d[b & 0xf]);
  }
  return s;
}

void wal_append_record(int fd, const uint8_t* data, size_t len) {
  if (fd < 0 || len > 0xffffffffu) return;
  uint8_t hdr[4] = {static_cast<uint8_t>(len >> 24), static_cast<uint8_t>(len >> 16),
                    static_cast<uint8_t>(len >> 8), static_cast<uint8_t>(len)};
  if (::write(fd, hdr, 4) != 4) return;
  if (len && ::write(fd, data, len) != static_cast<ssize_t>(len)) return;
  ::fsync(fd);
}

std::vector<malachite::Bytes> wal_load_records(int fd) {
  std::vector<malachite::Bytes> out;
  if (fd < 0) return out;
  ::lseek(fd, 0, SEEK_SET);
  for (;;) {
    uint8_t hdr[4];
    if (::read(fd, hdr, 4) != 4) break;
    uint32_t len = (uint32_t(hdr[0]) << 24) | (uint32_t(hdr[1]) << 16) | (uint32_t(hdr[2]) << 8) |
                   uint32_t(hdr[3]);
    malachite::Bytes rec(len);
    if (len && ::read(fd, rec.data(), len) != static_cast<ssize_t>(len)) break;
    out.push_back(std::move(rec));
  }
  ::lseek(fd, 0, SEEK_END);
  return out;
}

void wal_truncate(int fd) {
  if (fd < 0) return;
  if (::ftruncate(fd, 0) == 0) {
    ::lseek(fd, 0, SEEK_SET);
    ::fsync(fd);
  }
}

// reject a wrong-size key; padding would change the identity and AppHash
void copy_key32(consensus::Governance::Id& dst, const malachite::Bytes& pk) {
  if (pk.size() != 32) throw std::invalid_argument("hyle: validator public key must be 32 bytes");
  std::memcpy(dst.data(), pk.data(), 32);
}

std::vector<consensus::Governance::Member> genesis_members(const malachite::ValidatorSet& vs) {
  std::vector<consensus::Governance::Member> out;
  for (const auto& v : vs) {
    consensus::Governance::Id id{};
    copy_key32(id, v.public_key);
    out.push_back({id, id});
  }
  return out;
}

consensus::ValidatorSet genesis_set(const malachite::ValidatorSet& vs) {
  consensus::ValidatorSet out;
  for (const auto& v : vs) {
    consensus::Validator cv;
    copy_key32(cv.key, v.public_key);
    cv.power = v.voting_power ? v.voting_power : 1;
    out.push_back(cv);
  }
  return out;
}

consensus::ValidatorSet members_as_set(const consensus::Governance& g) {
  consensus::ValidatorSet out;
  for (const auto& m : g.members()) {
    consensus::Validator cv;
    cv.key = m.first;
    cv.power = 1;
    out.push_back(cv);
  }
  return out;
}

struct ParsedGov {
  std::vector<consensus::Governance::Member> members;
  std::vector<consensus::Governance::PendingVote> votes;
};
consensus::Governance::Kind decode_gov_kind(uint8_t k) {
  if (k > static_cast<uint8_t>(consensus::Governance::Kind::Remove))
    throw wire::Error("governance: kind out of range");
  return static_cast<consensus::Governance::Kind>(k);
}

ParsedGov parse_governance(wire::View gov) {
  wire::Reader r(gov);
  ParsedGov out;
  size_t n = r.count();
  for (size_t i = 0; i < n; ++i) {
    consensus::Governance::Id id{}, data{};
    std::memcpy(id.data(), r.raw(32).data(), 32);
    std::memcpy(data.data(), r.raw(32).data(), 32);
    out.members.push_back({id, data});
  }
  size_t nv = r.count();
  for (size_t i = 0; i < nv; ++i) {
    consensus::Governance::PendingVote pv;
    pv.kind = decode_gov_kind(r.u8());
    std::memcpy(pv.target.data(), r.raw(32).data(), 32);
    std::memcpy(pv.data.data(), r.raw(32).data(), 32);
    size_t nvoters = r.count();
    for (size_t j = 0; j < nvoters; ++j) {
      consensus::Governance::Id v{};
      std::memcpy(v.data(), r.raw(32).data(), 32);
      pv.voters.push_back(v);
    }
    out.votes.push_back(std::move(pv));
  }
  if (!r.empty()) throw wire::Error("governance: trailing bytes");
  return out;
}

consensus::ValidatorSet to_consensus_set(const malachite::ValidatorSet& vs) {
  consensus::ValidatorSet out;
  for (const auto& v : vs) {
    consensus::Validator cv;
    copy_key32(cv.key, v.public_key);
    cv.power = v.voting_power ? v.voting_power : 1;
    out.push_back(cv);
  }
  return out;
}

wire::Bytes gov_sign_bytes(consensus::Governance::Kind kind, const PubKey& target,
                           const std::array<uint8_t, 32>& data) {
  wire::Bytes out;
  wire::Writer w(out);
  w.raw(wire::View(reinterpret_cast<const uint8_t*>("HYLE_GOV_VOTE_V1"), 16));
  w.u8(static_cast<uint8_t>(kind));
  w.raw(wire::View(target.data(), target.size()));
  w.raw(wire::View(data.data(), data.size()));
  return out;
}

void put_gov(wire::Writer& w, const GovOp& g) {
  w.u8(static_cast<uint8_t>(g.kind));
  w.raw(wire::View(g.voter.data(), g.voter.size()));
  w.raw(wire::View(g.target.data(), g.target.size()));
  w.raw(wire::View(g.data.data(), g.data.size()));
  w.raw(wire::View(g.sig.data(), g.sig.size()));
}

GovOp get_gov(wire::Reader& r) {
  GovOp g;
  g.kind = decode_gov_kind(r.u8());
  wire::View voter = r.raw(32);
  std::memcpy(g.voter.data(), voter.data(), 32);
  wire::View target = r.raw(32);
  std::memcpy(g.target.data(), target.data(), 32);
  wire::View data = r.raw(32);
  std::memcpy(g.data.data(), data.data(), 32);
  wire::View sig = r.raw(64);
  std::memcpy(g.sig.data(), sig.data(), 64);
  return g;
}

} // namespace

Node::Node(KeyPair kp, malachite::ValidatorSet vset, StateMachine& sm, const NodeConfig& config)
    : kp_(kp), sm_(sm),
      chain_id_(config.chain_id.begin(), config.chain_id.end()),
      max_value_bytes_(config.max_value_bytes),
      cap_(std::max<unsigned>(config.member_cap, static_cast<unsigned>(vset.size()))),
      floor_(config.member_floor < 1 ? 1 : config.member_floor),
      gov_(genesis_members(vset), cap_, floor_), sched_(genesis_set(vset), 1, 2),
      block_retention_(config.block_retention), snapshot_interval_(config.snapshot_interval) {
  for (const auto& v : vset)
    if (v.voting_power > 1)
      throw std::invalid_argument("hyle: weighted genesis validator set unsupported (one-member-one-vote)");

  if (!config.data_dir.empty()) {
    std::error_code ec;
    std::filesystem::create_directories(config.data_dir, ec);
    std::string path = config.data_dir + "/votewal-" + pubkey_hex(kp_.pub) + ".bin";
    wal_fd_ = ::open(path.c_str(), O_RDWR | O_CREAT, 0600);
    if (wal_fd_ >= 0)
      boot_wal_ = wal_load_records(wal_fd_);
    else
      LOGWARNING << "vote WAL: cannot open " << path << " (double-sign protection off)";
  }
}

Node::~Node() {
  if (wal_fd_ >= 0) ::close(wal_fd_);
}

void Node::wal_append(malachite::BytesView entry) {
  if (wal_fd_ < 0 || wal_replaying_) return;
  wal_append_record(wal_fd_, entry.data, entry.size);
}

void Node::cache_value(malachite::BytesView value) {
  static constexpr size_t kMaxCachedValues = 4096;
  static constexpr size_t kMaxCachedBytes = 64 * 1024 * 1024;
  Hash vid = sha256(wv(value));
  if (value_cache_.emplace(vid, wire::Bytes(value.data, value.data + value.size)).second) {
    cache_order_.push_back(vid);
    cache_bytes_ += value.size;
    while (cache_order_.size() > 1 &&
           (cache_order_.size() > kMaxCachedValues || cache_bytes_ > kMaxCachedBytes)) {
      auto oit = value_cache_.find(cache_order_.front());
      if (oit != value_cache_.end()) {
        cache_bytes_ -= oit->second.size();
        value_cache_.erase(oit);
      }
      cache_order_.pop_front();
    }
  }
}

wire::Bytes Node::governance_canonical() const {
  wire::Bytes out;
  wire::Writer w(out);
  auto members = gov_.members();
  w.count(members.size());
  for (const auto& m : members) {
    w.raw(wire::View(m.first.data(), m.first.size()));
    w.raw(wire::View(m.second.data(), m.second.size()));
  }
  auto pend = gov_.pending();
  w.count(pend.size());
  for (const auto& pv : pend) {
    w.u8(static_cast<uint8_t>(pv.kind));
    w.raw(wire::View(pv.target.data(), pv.target.size()));
    w.raw(wire::View(pv.data.data(), pv.data.size()));
    w.count(pv.voters.size());
    for (const auto& v : pv.voters) w.raw(wire::View(v.data(), v.size()));
  }
  return out;
}

// sha256 over the three length-framed sections. adopt_snapshot must reproduce this layout.
static Hash composite_of(wire::View chain_id, wire::View gov, wire::View app) {
  wire::Bytes buf;
  wire::Writer w(buf);
  w.bytes(chain_id);
  w.bytes(gov);
  w.bytes(app);
  return sha256(wire::View(buf.data(), buf.size()));
}

Hash Node::composite_hash() const {
  if (!composite_dirty_) return composite_cache_;
  const wire::Bytes gov = governance_canonical();
  const wire::Bytes app = sm_.snapshot();
  composite_cache_ = composite_of(wire::View(chain_id_.data(), chain_id_.size()),
                                  wire::View(gov.data(), gov.size()),
                                  wire::View(app.data(), app.size()));
  composite_dirty_ = false;
  return composite_cache_;
}

bool Node::is_member(const PubKey& k) const { return gov_.isMember(k); }

wire::Bytes Node::build_envelope(const Hash& parent, const std::vector<GovOp>& gov,
                                 wire::View payload) const {
  wire::Bytes out;
  wire::Writer w(out);
  w.raw(wire::View(parent.data(), parent.size()));
  w.count(gov.size());
  for (const auto& g : gov) put_gov(w, g);
  w.raw(payload);
  return out;
}

Node::Envelope Node::split_envelope(wire::View value) const {
  wire::Reader r(value);
  Envelope e;
  wire::View p = r.raw(32);
  std::memcpy(e.parent.data(), p.data(), 32);
  size_t n = r.count();
  for (size_t i = 0; i < n; ++i) e.gov.push_back(get_gov(r));
  wire::View pl = r.raw(r.remaining());
  e.payload.assign(pl.begin(), pl.end());
  return e;
}

bool Node::validate_gov(const std::vector<GovOp>& gov) const {
  for (const auto& g : gov) {
    if (!gov_.isMember(g.voter)) return false;
    if (!hyle::verify(g.voter, gov_sign_bytes(g.kind, g.target, g.data), g.sig)) return false;
  }
  return true;
}

void Node::apply_gov(uint64_t height, const std::vector<GovOp>& gov) {
  bool changed = false;
  for (const auto& g : gov) {
    if (!gov_.isMember(g.voter)) continue;
    if (!hyle::verify(g.voter, gov_sign_bytes(g.kind, g.target, g.data), g.sig)) continue;
    if (gov_.vote(g.voter, g.kind, g.target, g.data)) changed = true;
  }
  if (changed) {
    sched_.onDecided(height, members_as_set(gov_));
    LOGDEBUG << "governance changed at height " << height << "; members now " << gov_.size();
  }
}

malachite::Bytes Node::sign(malachite::BytesView m) {
  Sig s = kp_.sign(wv(m));
  return malachite::Bytes(s.begin(), s.end());
}

bool Node::verify(malachite::BytesView m, malachite::BytesView pk, malachite::BytesView sig) {
  if (pk.size != 32 || sig.size != 64) return false;
  PubKey pub{};
  Sig s{};
  std::memcpy(pub.data(), pk.data, pub.size());
  std::memcpy(s.data(), sig.data, s.size());
  return hyle::verify(pub, wv(m), s);
}

bool Node::validate(malachite::BytesView value) { return accept_proposed(value); }

bool Node::accept_proposed(malachite::BytesView value) {
  if (max_value_bytes_ > 0 && value.size > max_value_bytes_) {
    LOGDEBUG << "reject proposal: oversized value " << value.size << " > " << max_value_bytes_;
    return false;
  }
  cache_value(value);
  try {
    Envelope e = split_envelope(wv(value));
    if (!(e.parent == composite_hash())) {  // must build on my committed state
      LOGDEBUG << "reject proposal: stale parent (not built on committed state)";
      return false;
    }
    if (!validate_gov(e.gov)) {
      LOGDEBUG << "reject proposal: invalid governance op (non-member or bad signature)";
      return false;
    }
    if (!sm_.validate_payload(wire::View(e.payload))) {
      LOGDEBUG << "reject proposal: application rejected payload";
      return false;
    }
    LOGTRACE << "accept proposal: " << e.gov.size() << " gov ops, payload " << e.payload.size()
             << "B";
    return true;
  } catch (const wire::Error& ex) {
    LOGDEBUG << "reject proposal: malformed envelope (" << ex.what() << ")";
    return false;
  }
}

void Node::publish(PublishKind, malachite::BytesView m) { outbox_.push_back(m.to_owned()); }

void Node::schedule_timeout(malachite::Timeout t, uint64_t dur) {
  timers_.push_back(Timer{t.kind, t.round.value, dur});
}

void Node::cancel_timeout(malachite::Timeout t) {
  for (auto it = timers_.begin(); it != timers_.end();) {
    if (it->kind == t.kind && it->round == t.round.value)
      it = timers_.erase(it);
    else
      ++it;
  }
}

void Node::cancel_all_timeouts() { timers_.clear(); }
void Node::reset_timeouts() { timers_.clear(); }

void Node::on_error(ErrorCode code, malachite::BytesView message) {
  std::string msg(reinterpret_cast<const char*>(message.data), message.size);
  switch (code) {
    case ErrorCode::Undecodable:
      LOGDEBUG << "consensus: " << msg;
      break;
    default:
      LOGWARNING << "consensus: " << msg << " (code " << static_cast<uint32_t>(code) << ")";
      break;
  }
}

void Node::submit_gov_vote(consensus::Governance::Kind kind, const PubKey& target,
                           const std::array<uint8_t, 32>& data) {
  GovOp g;
  g.kind = kind;
  g.voter = kp_.pub;
  g.target = target;
  g.data = data;
  g.sig = kp_.sign(gov_sign_bytes(kind, target, data));
  pending_gov_.push_back(g);
  LOGDEBUG << "submit governance vote: kind " << static_cast<int>(kind) << VAL("target", target);
}

void Node::get_value(malachite::Height h, malachite::Round r, uint64_t) {
  Hash parent = composite_hash();
  wire::Bytes payload = sm_.build_payload(h);
  pending_value_ = build_envelope(parent, pending_gov_, payload);
  LOGDEBUG << "propose height " << h << " round " << r.value << ": " << pending_gov_.size()
           << " gov ops, payload " << payload.size() << "B";
  pending_gov_.clear();
  cache_value(malachite::BytesView(pending_value_));
  ph_ = h;
  pr_ = r;
  want_propose_ = true;
}

void Node::decide(const malachite::Decision& d) {
  bool applied = false;
  try {
    if (d.value_id.size == 32) {
      Hash vid{};
      std::memcpy(vid.data(), d.value_id.data, vid.size());
      auto it = value_cache_.find(vid);
      if (it != value_cache_.end()) {
        Envelope e = split_envelope(wire::View(it->second));
        // must build on our committed state; for a synced block this authenticates the snapshot
        if (!(e.parent == composite_hash())) throw wire::Error("decide: parent mismatch");
        // all-or-none: apply the app payload (the only step that can throw) before mutating governance
        ApplyContext ctx;
        ctx.height = d.height;
        auto pit = proposers_.find({d.height, d.round.value});
        if (pit != proposers_.end()) ctx.proposer = pit->second;
        // The active validator set at this height (validators_for -- the +2-scheduled set that
        // committed this block, not the immediate governance membership), for an app that runs
        // its own vote-gated acts.
        const malachite::ValidatorSet setH = validators_for(d.height);
        for (const auto& v : setH) {
          PubKey k{};
          std::memcpy(k.data(), v.public_key.data(), k.size());
          ctx.members.push_back(k);
        }
        ctx.quorum = static_cast<unsigned>((2 * setH.size()) / 3 + 1);
        sm_.apply_payload(ctx, wire::View(e.payload));
        apply_gov(d.height, e.gov);
        // Validators dropped from the active set at this height, so the app can reclaim their
        // per-validator state. Uses validators_for, not the governance settle, so a validator
        // still active during the +2 window is not cleared early.
        if (d.height >= 2) {
          const malachite::ValidatorSet setPrev = validators_for(d.height - 1);
          std::vector<PubKey> removed;
          for (const auto& p : setPrev) {
            bool still = false;
            for (const auto& c : setH)
              if (c.public_key == p.public_key) { still = true; break; }
            if (!still) {
              PubKey k{};
              std::memcpy(k.data(), p.public_key.data(), k.size());
              removed.push_back(k);
            }
          }
          if (!removed.empty()) sm_.on_validators_removed(removed);
        }
        composite_dirty_ = true;
        applied = true;
        last_att_.height = d.height;
        last_att_.app_hash = composite_hash();
        last_att_.signer = kp_.pub;
        last_att_.sig = kp_.sign(attestation_bytes(d.height, last_att_.app_hash));
        LOGINFO << "commit height " << d.height << " (round " << d.round.value << ", gov "
                << e.gov.size() << ", payload " << e.payload.size() << "B)"
                << VAL("apphash", last_att_.app_hash) << VAL("proposer", ctx.proposer);
        if (d.certificate.size > 0) {
          Block blk;
          blk.proposer = ctx.proposer;
          blk.value.assign(it->second.begin(), it->second.end());
          blk.certificate.assign(d.certificate.data, d.certificate.data + d.certificate.size);
          blocks_[d.height] = std::move(blk);
        } else {
          LOGWARNING << "decided height " << d.height << " with empty certificate; not retained for sync";
        }
      }
    }
  } catch (...) {
    applied = false;
  }
  if (!applied) {
    decide_misses_++;
    LOGWARNING << "decide miss at height " << d.height << " (value unresolved or parent mismatch)";
  }
  if (d.height > last_decided_) last_decided_ = d.height;
  if (applied && d.height == applied_height_ + 1) applied_height_ = d.height;
  for (auto it = proposers_.begin(); it != proposers_.end();) {
    if (it->first.first <= d.height)
      it = proposers_.erase(it);
    else
      ++it;
  }
  if (applied && snapshot_interval_ > 0 && d.height % snapshot_interval_ == 0) {
    // self-attested: served to joiners, which pool attestations from many peers into a quorum
    last_snapshot_ = build_snapshot({last_att_});
    last_snapshot_height_ = d.height;
    has_snapshot_ = true;
    LOGINFO << "snapshot taken at height " << d.height;
  }
  if (snapshot_interval_ > 0) {
    while (!blocks_.empty() && blocks_.begin()->first <= last_snapshot_height_)
      blocks_.erase(blocks_.begin());
  } else {
    while (!blocks_.empty() && blocks_.begin()->first + block_retention_ <= last_decided_)
      blocks_.erase(blocks_.begin());
  }
  if (!blocks_.empty())
    LOGTRACE << "block window [" << blocks_.begin()->first << ".." << blocks_.rbegin()->first
             << "], " << blocks_.size() << " blocks";

  if (!wal_replaying_) wal_truncate(wal_fd_);
}

void Node::start_round(malachite::Height h, malachite::Round r, malachite::BytesView proposer,
                       malachite::Role) {
  if (proposer.size == 32) {
    PubKey p{};
    std::memcpy(p.data(), proposer.data, 32);
    proposers_[{h, r.value}] = p;
    LOGTRACE << "start round: height " << h << " round " << r.value << VAL("proposer", p);
  }
}

malachite::ValidatorSet Node::validators_for(malachite::Height h) const {
  malachite::ValidatorSet out;
  for (const auto& cv : sched_.setForHeight(h)) {
    malachite::Validator v;
    v.address = malachite::Bytes(cv.key.begin(), cv.key.end());
    v.public_key = v.address;
    v.voting_power = cv.power;
    out.push_back(v);
  }
  return out;
}

bool Node::get_validator_set(malachite::Height h, malachite::ValidatorSet& out) {
  out = validators_for(h);
  return true;
}

void Node::sync_value(malachite::Height h, malachite::Round r, malachite::BytesView proposer,
                      malachite::BytesView value) {
  got_sync_ = true;
  sync_h_ = h;
  sync_r_ = r;
  sync_value_.assign(value.data, value.data + value.size);
  cache_value(value);
  // the sync path has no start_round, so without this decide() skips the block reward, forking state
  if (proposer.size == 32) {
    PubKey p{};
    std::memcpy(p.data(), proposer.data, 32);
    proposers_[{h, r.value}] = p;
  }
  LOGDEBUG << "sync value received for height " << h << " (round " << r.value << ", "
           << value.size << "B)";
}

Snapshot Node::build_snapshot(std::vector<Attestation> attestations) const {
  Snapshot s;
  s.height = last_decided_;
  s.governance = governance_canonical();
  s.app = sm_.snapshot();
  s.next_set = validators_for(last_decided_ + 1);
  s.next_set2 = validators_for(last_decided_ + 2);
  s.attestations = std::move(attestations);
  return s;
}

bool Node::adopt_snapshot(const Snapshot& s, const malachite::ValidatorSet& trusted) {
  const Hash expected = composite_of(wire::View(chain_id_.data(), chain_id_.size()),
                                     wire::View(s.governance.data(), s.governance.size()),
                                     wire::View(s.app.data(), s.app.size()));

  uint64_t total = 0;
  for (const auto& v : trusted) total += v.voting_power ? v.voting_power : 1;
  const wire::Bytes msg = attestation_bytes(s.height, expected);
  std::set<PubKey> counted;
  uint64_t got = 0;
  for (const auto& a : s.attestations) {
    if (a.height != s.height || !(a.app_hash == expected)) continue;
    if (counted.count(a.signer)) continue;
    uint64_t power = 0;
    for (const auto& v : trusted) {
      if (v.public_key.size() == 32 && std::memcmp(v.public_key.data(), a.signer.data(), 32) == 0) {
        power = v.voting_power ? v.voting_power : 1;
        break;
      }
    }
    if (power == 0) continue;
    if (!hyle::verify(a.signer, msg, a.sig)) continue;
    counted.insert(a.signer);
    got += power;
  }
  if (got * 3 <= total * 2) {
    LOGWARNING << "reject snapshot at height " << s.height << ": attestation quorum not met ("
               << got << "/" << total << " power)";
    return false;
  }

  LOGINFO << "adopt snapshot at height " << s.height << " (quorum " << got << "/" << total
          << " power)" << VAL("apphash", expected);
  return restore_snapshot(s);
}

bool Node::restore_snapshot(const Snapshot& s) {
  // decode everything that can throw into locals before mutating node state, so malformed input is rejected, not a crash
  try {
    ParsedGov pg = parse_governance(s.governance);
    consensus::ValidatorSet next = to_consensus_set(s.next_set);
    consensus::ValidatorSet next2 = to_consensus_set(s.next_set2);
    sm_.restore(wire::View(s.app));
    gov_ = consensus::Governance(pg.members, cap_, floor_);
    gov_.set_pending(pg.votes);
    sched_ = consensus::ValidatorSetSchedule(next, s.height + 1, 2);
    // a change decided at this height is effective at +2 but not replayed; carry it
    if (!(next2 == next)) sched_.set_change(s.height + 2, next2);
    last_decided_ = s.height;
    applied_height_ = s.height;
    composite_dirty_ = true;
    LOGDEBUG << "restore snapshot: resume at height " << (s.height + 1) << ", " << gov_.size()
             << " members, " << pg.votes.size() << " pending votes";
    return true;
  } catch (const wire::Error& ex) {
    LOGWARNING << "reject snapshot: malformed state (" << ex.what() << ")";
    return false;
  }
}

std::vector<malachite::Bytes> Node::drain_outbox() {
  std::vector<malachite::Bytes> out = std::move(outbox_);
  outbox_.clear();
  return out;
}

Timer Node::take_timer(size_t idx) {
  Timer t = timers_.at(idx);
  timers_.erase(timers_.begin() + static_cast<long>(idx));
  return t;
}

} // namespace hyle
