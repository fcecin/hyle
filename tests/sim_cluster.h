#pragma once

#include <hyle/core/crypto.h>
#include <hyle/core/node.h>
#include <hyle/core/snapshot.h>
#include <hyle/core/state_machine.h>

#include <malachite/engine.hpp>

#include <cstdint>
#include <map>
#include <memory>
#include <utility>
#include <vector>

namespace simnet {

struct Rng {
  uint64_t s;
  explicit Rng(uint64_t seed) : s(seed) {}
  uint64_t next() {
    uint64_t z = (s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
  }
  uint32_t below(uint32_t n) { return n == 0 ? 0 : static_cast<uint32_t>(next() % n); }
  bool chance(uint32_t pct) { return below(100) < pct; }
};

} // namespace simnet

enum class Byz { None, Silent, BadPropose, Equivocate };

struct SimConfig {
  uint64_t seed = 1;
  uint32_t loss_pct = 0;
  uint32_t max_delay = 1;
  uint32_t dup_pct = 0;
  uint64_t gst_tick = 0;
};

struct SimCluster {
  int n;
  std::vector<std::unique_ptr<hyle::Node>> nodes;
  std::vector<std::unique_ptr<malachite::Engine>> engines;
  std::vector<char> active;
  std::vector<Byz> role;
  malachite::ValidatorSet vset;
  SimConfig cfg;
  simnet::Rng rng;

  explicit SimCluster(const std::vector<hyle::StateMachine*>& sms, SimConfig c = {})
      : n(static_cast<int>(sms.size())), active(sms.size(), 1), role(sms.size(), Byz::None),
        cfg(c), rng(c.seed ? c.seed : 1) {
    std::vector<hyle::KeyPair> kps;
    for (int i = 0; i < n; i++) {
      hyle::PrivKey secret{};
      secret[0] = static_cast<uint8_t>(i & 0xff);
      secret[1] = static_cast<uint8_t>((i >> 8) & 0xff);
      secret[31] = 0xA5;
      hyle::KeyPair kp = hyle::KeyPair::from_secret(secret);
      kps.push_back(kp);
      malachite::Validator v;
      v.address = malachite::Bytes(kp.pub.begin(), kp.pub.end());
      v.public_key = v.address;
      v.voting_power = 1;
      vset.push_back(v);
    }
    for (int i = 0; i < n; i++) {
      hyle::NodeConfig nc;
      nodes.push_back(std::make_unique<hyle::Node>(kps[i], vset, *sms[i], nc));
      malachite::Bytes addr(kps[i].pub.begin(), kps[i].pub.end());
      engines.push_back(std::make_unique<malachite::Engine>(
          make_cfg(std::move(addr), 1, vset), *nodes[i]));
    }
  }

  static malachite::Config make_cfg(malachite::Bytes address, uint64_t initial_height,
                                    const malachite::ValidatorSet& set) {
    malachite::Config cfg;
    cfg.address = std::move(address);
    cfg.initial_height = initial_height;
    cfg.initial_validator_set = set;
    cfg.value_payload = malachite::ValuePayload::PartsOnly;
    return cfg;
  }

  void set_role(int i, Byz b) { role[i] = b; }
  void deactivate(int i) { active[i] = 0; }

  enum class Kind { Msg, Prop, Timeout };
  struct Ev {
    Kind kind = Kind::Msg;
    int to = 0;
    malachite::Bytes bytes;
    malachite::Height h = 0;
    malachite::Round r = malachite::Round::nil();
    malachite::Bytes prop;
    hyle::Timer timer;
  };
  static constexpr uint64_t kTimeoutScale = 50;
  uint64_t byz_props = 0;
  uint64_t dropped = 0;
  uint64_t duped = 0;
  uint64_t split = 0;
  std::multimap<uint64_t, Ev> queue;
  std::vector<uint64_t> started;
  uint64_t now = 0;

  void schedule(uint64_t tick, Ev e) { queue.emplace(tick, std::move(e)); }

  static malachite::Bytes corrupt(const malachite::Bytes& v) {
    malachite::Bytes b = v;
    if (b.empty()) b.push_back(0x01);
    else b[0] ^= 0xFF;
    return b;
  }

  uint64_t delay() { return reliable() ? 1 : 1 + rng.below(cfg.max_delay); }
  bool reliable() const { return now >= cfg.gst_tick; }

  void harvest() {
    for (int i = 0; i < n; i++) {
      if (!active[i] || !nodes[i]->wants_propose()) continue;
      malachite::Height h = nodes[i]->proposal_height();
      malachite::Round r = nodes[i]->proposal_round();
      malachite::Bytes val = nodes[i]->proposal_value().to_owned();
      nodes[i]->clear_proposal();
      if (role[i] == Byz::Silent) continue;
      hyle::PubKey ppk = nodes[i]->pubkey();
      malachite::Bytes paddr(ppk.begin(), ppk.end());
      engines[i]->propose(h, r, malachite::BytesView(val));
      if (role[i] == Byz::BadPropose || role[i] == Byz::Equivocate) ++byz_props;
      for (int j = 0; j < n; j++) {
        if (j == i || !active[j]) continue;
        malachite::Bytes seen = val;
        if (role[i] == Byz::BadPropose) seen = corrupt(val);
        else if (role[i] == Byz::Equivocate && (j & 1)) { seen = corrupt(val); ++split; }
        Ev e;
        e.kind = Kind::Prop;
        e.to = j;
        e.bytes = std::move(seen);
        e.h = h;
        e.r = r;
        e.prop = paddr;
        schedule(now + delay(), std::move(e));
      }
    }
    for (int i = 0; i < n; i++) {
      if (!active[i]) continue;
      auto out = nodes[i]->drain_outbox();
      if (role[i] == Byz::Silent) continue;
      const bool rel = reliable();
      for (auto& m : out)
        for (int j = 0; j < n; j++) {
          if (j == i || !active[j]) continue;
          if (!rel && rng.chance(cfg.loss_pct)) { ++dropped; continue; }
          Ev e;
          e.kind = Kind::Msg;
          e.to = j;
          e.bytes = m;
          schedule(now + delay(), e);
          if (!rel && rng.chance(cfg.dup_pct)) { schedule(now + delay(), e); ++duped; }
        }
    }
    for (int i = 0; i < n; i++) {
      if (!active[i]) continue;
      while (!nodes[i]->timers().empty()) {
        Ev e;
        e.kind = Kind::Timeout;
        e.to = i;
        e.timer = nodes[i]->take_timer(0);
        uint64_t d = e.timer.dur / kTimeoutScale;
        schedule(now + (d ? d : 1), std::move(e));
      }
    }
  }

  void process(const Ev& e) {
    if (!active[e.to]) return;
    switch (e.kind) {
      case Kind::Msg:
        engines[e.to]->recv(malachite::BytesView(e.bytes));
        break;
      case Kind::Prop: {
        bool ok = nodes[e.to]->accept_proposed(malachite::BytesView(e.bytes));
        engines[e.to]->proposed_value(e.h, e.r, malachite::Round::nil(),
                                      malachite::BytesView(e.prop), malachite::BytesView(e.bytes),
                                      ok, malachite::ValueOrigin::Consensus);
        break;
      }
      case Kind::Timeout:
        engines[e.to]->timeout_elapsed(
            malachite::Timeout{e.timer.kind, malachite::Round{e.timer.round}});
        break;
    }
  }

  int committed(uint64_t h) const {
    int c = 0;
    for (int i = 0; i < n; i++)
      if (active[i] && nodes[i]->applied_height() >= h) c++;
    return c;
  }

  void catch_up_one(int behind, int source) {
    uint64_t H0 = nodes[behind]->applied_height();
    uint64_t tip = nodes[source]->applied_height();
    if (tip <= H0) return;
    hyle::PubKey pk = nodes[behind]->pubkey();
    engines[behind] = std::make_unique<malachite::Engine>(
        make_cfg(malachite::Bytes(pk.begin(), pk.end()), H0 + 1, vset), *nodes[behind]);
    for (auto& hb : nodes[source]->blocks_after(H0)) {
      uint64_t h = hb.first;
      if (h > tip) break;
      const hyle::Block& blk = hb.second;
      engines[behind]->start_height(h, nodes[behind]->validators_for(h));
      malachite::Bytes prop(blk.proposer.begin(), blk.proposer.end());
      engines[behind]->sync_value_response(malachite::BytesView(prop),
                                           malachite::BytesView(blk.value),
                                           malachite::BytesView(blk.certificate));
      if (nodes[behind]->got_sync()) {
        engines[behind]->proposed_value(nodes[behind]->sync_height(), nodes[behind]->sync_round(),
                                        malachite::Round::nil(), malachite::BytesView(prop),
                                        malachite::BytesView(blk.value), true,
                                        malachite::ValueOrigin::Sync);
        nodes[behind]->clear_sync();
      }
    }
    started[behind] = nodes[behind]->last_decided();
  }

  void catch_up_laggards() {
    int src = -1;
    uint64_t tip = 0;
    for (int i = 0; i < n; i++)
      if (active[i] && nodes[i]->applied_height() >= tip) { tip = nodes[i]->applied_height(); src = i; }
    if (src < 0 || tip == 0) return;
    const uint64_t thresh = n <= 32 ? 1 : 2;
    for (int i = 0; i < n; i++)
      if (active[i] && i != src && nodes[i]->applied_height() + thresh <= tip) catch_up_one(i, src);
  }

  void advance_heights(uint64_t goal) {
    for (int i = 0; i < n; i++) {
      if (!active[i]) continue;
      while (started[i] <= goal && nodes[i]->last_decided() >= started[i]) {
        ++started[i];
        if (started[i] <= goal)
          engines[i]->start_height(started[i], nodes[i]->validators_for(started[i]));
      }
    }
  }

  bool run(uint64_t goal, int needed, uint64_t max_events = 4000000) {
    uint64_t done = 0, iters = 0, last_sync = 0;
    const uint64_t sync_iters = 10;
    started.assign(n, 0);
    advance_heights(goal);
    harvest();
    while (done <= max_events) {
      ++iters;
      if (committed(goal) >= needed) return true;
      if (iters - last_sync >= sync_iters) {
        catch_up_laggards();
        advance_heights(goal);
        harvest();
        last_sync = iters;
      }
      if (queue.empty()) {
        catch_up_laggards();
        advance_heights(goal);
        harvest();
        if (queue.empty()) return committed(goal) >= needed;
      }
      now = queue.begin()->first;
      auto range = queue.equal_range(now);
      std::vector<Ev> batch;
      for (auto it = range.first; it != range.second; ++it) batch.push_back(std::move(it->second));
      queue.erase(range.first, range.second);
      for (const Ev& e : batch) { process(e); ++done; }
      advance_heights(goal);
      harvest();
    }
    return false;
  }

  bool all_agree() const {
    hyle::Hash ref{};
    bool have = false;
    for (int i = 0; i < n; i++) {
      if (!active[i]) continue;
      hyle::Hash h = nodes[i]->composite_hash();
      if (!have) { ref = h; have = true; }
      else if (!(h == ref)) return false;
    }
    return have;
  }
};
