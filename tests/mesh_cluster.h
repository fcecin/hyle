#pragma once

#include <hyle/core/node.h>
#include <hyle/services/app.h>
#include <hyle/services/genesis.h>

#include <malachite/engine.hpp>

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <utility>
#include <vector>

#include "sim_cluster.h"

namespace hyle::morphe {
using namespace hyle::services;

inline std::vector<KeyPair> mesh_keys(int n) {
  std::vector<KeyPair> kps;
  for (int i = 0; i < n; i++) {
    PrivKey secret{};
    secret[0] = static_cast<uint8_t>(i & 0xff);
    secret[1] = static_cast<uint8_t>((i >> 8) & 0xff);
    secret[31] = 0xA5;
    kps.push_back(KeyPair::from_secret(secret));
  }
  return kps;
}

inline Genesis mesh_genesis(const std::vector<KeyPair>& kps) {
  Genesis g;
  g.chain_id = "morphe-mesh";
  for (const auto& kp : kps) g.validators.push_back(kp.pub);
  return g;
}

struct MorpheMeshCluster {
  int n;
  std::vector<std::unique_ptr<App>> apps;
  std::vector<std::unique_ptr<hyle::Node>> nodes;
  std::vector<std::unique_ptr<malachite::Engine>> engines;
  std::vector<char> active;
  std::vector<KeyPair> kps;
  malachite::ValidatorSet vset;
  simnet::Rng rng;

  std::vector<std::set<int>> links;
  uint32_t loss_pct = 0;

  uint64_t relay_used = 0;
  uint64_t partition_drop = 0;
  uint64_t loss_drop = 0;

  explicit MorpheMeshCluster(int n_, const Genesis& g, uint64_t seed = 1)
      : n(n_), active(n_, 1), kps(mesh_keys(n_)), rng(seed ? seed : 1), links(n_) {
    for (int i = 0; i < n; i++) {
      malachite::Validator v;
      v.address = malachite::Bytes(kps[i].pub.begin(), kps[i].pub.end());
      v.public_key = v.address;
      v.voting_power = 1;
      vset.push_back(v);
    }
    for (int i = 0; i < n; i++) {
      apps.push_back(std::make_unique<App>(App::from_genesis(g)));
      hyle::NodeConfig nc;
      nc.chain_id = g.chain_id;
      nodes.push_back(std::make_unique<hyle::Node>(kps[i], vset, *apps[i], nc));
      malachite::Bytes addr(kps[i].pub.begin(), kps[i].pub.end());
      engines.push_back(std::make_unique<malachite::Engine>(make_cfg(std::move(addr), 1, vset),
                                                            *nodes[i]));
    }
    for (int i = 0; i < n; i++)
      for (int j = 0; j < n; j++)
        if (i != j) links[i].insert(j);
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

  void deactivate(int i) { active[i] = 0; }
  void reactivate(int i) { active[i] = 1; }
  bool linked(int a, int b) const { return links[a].count(b) != 0; }
  void down(int a, int b) { links[a].erase(b); links[b].erase(a); }
  void up(int a, int b) { links[a].insert(b); links[b].insert(a); }
  void isolate(int i) {
    for (int j = 0; j < n; j++) if (j != i) down(i, j);
  }
  void reconnect(int i) {
    for (int j = 0; j < n; j++) if (j != i && active[j]) up(i, j);
  }

  enum class Reach { Direct, Relay, None };
  Reach reachability(int from, int to) const {
    if (linked(from, to)) return Reach::Direct;
    for (int r = 0; r < n; r++)
      if (r != from && r != to && active[r] && linked(from, r) && linked(r, to)) return Reach::Relay;
    return Reach::None;
  }

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
  std::multimap<uint64_t, Ev> queue;
  std::vector<uint64_t> started;
  uint64_t now = 0;

  void schedule(uint64_t tick, Ev e) { queue.emplace(tick, std::move(e)); }

  void route(int i, int j, Ev e) {
    Reach rc = reachability(i, j);
    if (rc == Reach::None) { ++partition_drop; return; }
    uint64_t hops = (rc == Reach::Relay) ? 2 : 1;
    if (rc == Reach::Relay) ++relay_used;
    for (uint64_t hop = 0; hop < hops; hop++)
      if (loss_pct != 0 && rng.below(100) < loss_pct) { ++loss_drop; return; }
    schedule(now + hops, std::move(e));
  }

  void harvest() {
    for (int i = 0; i < n; i++) {
      if (!active[i] || !nodes[i]->wants_propose()) continue;
      malachite::Height h = nodes[i]->proposal_height();
      malachite::Round r = nodes[i]->proposal_round();
      malachite::Bytes val = nodes[i]->proposal_value().to_owned();
      nodes[i]->clear_proposal();
      hyle::PubKey ppk = nodes[i]->pubkey();
      malachite::Bytes paddr(ppk.begin(), ppk.end());
      engines[i]->propose(h, r, malachite::BytesView(val));
      for (int j = 0; j < n; j++) {
        if (j == i || !active[j]) continue;
        Ev e;
        e.kind = Kind::Prop;
        e.to = j;
        e.bytes = val;
        e.h = h;
        e.r = r;
        e.prop = paddr;
        route(i, j, std::move(e));
      }
    }
    for (int i = 0; i < n; i++) {
      if (!active[i]) continue;
      for (auto& m : nodes[i]->drain_outbox())
        for (int j = 0; j < n; j++) {
          if (j == i || !active[j]) continue;
          Ev e;
          e.kind = Kind::Msg;
          e.to = j;
          e.bytes = m;
          route(i, j, std::move(e));
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
      if (active[i] && i != src && nodes[i]->applied_height() + thresh <= tip &&
          reachability(src, i) != Reach::None)
        catch_up_one(i, src);
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

  bool run(uint64_t goal, int needed, uint64_t max_events = 4000000,
           const std::function<void(MorpheMeshCluster&, uint64_t)>& tick_hook = {}) {
    uint64_t done = 0, iters = 0, last_sync = 0;
    const uint64_t sync_iters = 10;
    started.assign(n, 0);
    advance_heights(goal);
    harvest();
    while (done <= max_events) {
      ++iters;
      if (tick_hook) tick_hook(*this, iters);
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

} // namespace hyle::morphe
