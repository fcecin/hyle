#pragma once

#include <hyle/core/crypto.h>
#include <hyle/core/node.h>
#include <hyle/core/snapshot.h>
#include <hyle/core/state_machine.h>

#include <malachite/engine.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

struct LocalCluster {
  int n;
  std::vector<std::unique_ptr<hyle::Node>> nodes;
  std::vector<std::unique_ptr<malachite::Engine>> engines;
  std::vector<char> active;
  malachite::ValidatorSet vset;
  uint64_t target = 0;
  std::string chain_id;
  std::string data_dir;
  std::vector<hyle::KeyPair> kps;
  std::vector<hyle::StateMachine*> sm_ptrs;
  uint64_t retention = 1024;
  uint64_t snap_interval = 0;

  explicit LocalCluster(const std::vector<hyle::StateMachine*>& sms, uint64_t block_retention = 1024,
                        uint64_t snapshot_interval = 0, int genesis_count = -1,
                        std::string chain = {}, std::string data = {})
      : n(static_cast<int>(sms.size())), active(sms.size(), 1), chain_id(std::move(chain)),
        data_dir(std::move(data)), sm_ptrs(sms), retention(block_retention),
        snap_interval(snapshot_interval) {
    const int g = genesis_count < 0 ? n : genesis_count;
    for (int i = 0; i < n; i++) {
      hyle::PrivKey secret{};
      secret[0] = static_cast<uint8_t>(i & 0xff);
      secret[1] = static_cast<uint8_t>((i >> 8) & 0xff);
      secret[31] = 0xA5;
      hyle::KeyPair kp = hyle::KeyPair::from_secret(secret);
      kps.push_back(kp);
      if (i < g) {
        malachite::Validator v;
        v.address = malachite::Bytes(kp.pub.begin(), kp.pub.end());
        v.public_key = v.address;
        v.voting_power = 1;
        vset.push_back(v);
      }
    }
    for (int i = 0; i < n; i++) {
      nodes.push_back(std::make_unique<hyle::Node>(kps[i], vset, *sm_ptrs[i], node_cfg()));
      malachite::Bytes addr(kps[i].pub.begin(), kps[i].pub.end());
      engines.push_back(std::make_unique<malachite::Engine>(make_cfg(addr, 1, vset), *nodes[i]));
      active[i] = (i < g) ? 1 : 0;
    }
  }

  hyle::NodeConfig node_cfg() const {
    hyle::NodeConfig cfg;
    cfg.block_retention = retention;
    cfg.snapshot_interval = snap_interval;
    cfg.chain_id = chain_id;
    cfg.data_dir = data_dir;
    return cfg;
  }

  size_t crash_wal(int i) {
    nodes[i] = std::make_unique<hyle::Node>(kps[i], vset, *sm_ptrs[i], node_cfg());
    uint64_t resume = nodes[i]->last_decided() + 1;
    malachite::Bytes addr(kps[i].pub.begin(), kps[i].pub.end());
    malachite::ValidatorSet set = nodes[i]->validators_for(resume);
    engines[i] = std::make_unique<malachite::Engine>(make_cfg(addr, resume, set), *nodes[i]);
    size_t replayed = nodes[i]->boot_wal().size();
    nodes[i]->begin_wal_replay();
    engines[i]->start_height(resume, set);
    for (auto& e : nodes[i]->boot_wal()) engines[i]->wal_replay(e);
    nodes[i]->end_wal_replay();
    active[i] = 1;
    return replayed;
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

  void start(uint64_t h) {
    for (int i = 0; i < n; i++)
      if (active[i]) engines[i]->start_height(h, nodes[i]->validators_for(h));
  }

  bool pump() {
    bool progress = false;
    for (int i = 0; i < n; i++) {
      if (!active[i] || !nodes[i]->wants_propose()) continue;
      malachite::Height h = nodes[i]->proposal_height();
      malachite::Round r = nodes[i]->proposal_round();
      malachite::Bytes val = nodes[i]->proposal_value().to_owned();
      nodes[i]->clear_proposal();
      engines[i]->propose(h, r, malachite::BytesView(val));
      progress = true;
      hyle::PubKey ppk = nodes[i]->pubkey();
      malachite::Bytes paddr(ppk.begin(), ppk.end());
      for (int j = 0; j < n; j++) {
        if (j == i || !active[j]) continue;
        bool ok = nodes[j]->accept_proposed(malachite::BytesView(val));
        engines[j]->proposed_value(h, r, malachite::Round::nil(), malachite::BytesView(paddr),
                                   malachite::BytesView(val), ok, malachite::ValueOrigin::Consensus);
      }
    }
    std::vector<std::pair<int, malachite::Bytes>> msgs;
    for (int i = 0; i < n; i++)
      if (active[i])
        for (auto& m : nodes[i]->drain_outbox()) msgs.emplace_back(i, std::move(m));
    for (auto& pm : msgs)
      for (int j = 0; j < n; j++)
        if (j != pm.first && active[j]) {
          engines[j]->recv(malachite::BytesView(pm.second));
          progress = true;
        }
    return progress;
  }

  bool fire_one_timeout() {
    int bn = -1;
    size_t bi = 0;
    uint64_t best = UINT64_MAX;
    for (int i = 0; i < n; i++) {
      if (!active[i]) continue;
      const auto& ts = nodes[i]->timers();
      for (size_t k = 0; k < ts.size(); k++)
        if (ts[k].dur < best) {
          best = ts[k].dur;
          bn = i;
          bi = k;
        }
    }
    if (bn < 0) return false;
    hyle::Timer t = nodes[bn]->take_timer(bi);
    engines[bn]->timeout_elapsed(malachite::Timeout{t.kind, malachite::Round{t.round}});
    return true;
  }

  int committed(uint64_t h) const {
    int c = 0;
    for (int i = 0; i < n; i++)
      if (active[i] && nodes[i]->applied_height() >= h) c++;
    return c;
  }

  void run_to(uint64_t goal, int needed, int max_ticks = 200000) {
    if (target == 0) {
      target = 1;
      start(1);
    }
    for (int tick = 0; tick < max_ticks; tick++) {
      bool progress = pump();
      if (committed(target) >= needed) {
        if (target >= goal) return;
        target++;
        start(target);
        continue;
      }
      if (!progress && !fire_one_timeout()) return;
    }
  }

  void run(uint64_t heights, int needed, int max_ticks = 200000) {
    target = 0;
    run_to(heights, needed, max_ticks);
  }

  void join(int i, const hyle::Snapshot& snap, const malachite::ValidatorSet& trusted) {
    nodes[i]->adopt_snapshot(snap, trusted);
    malachite::ValidatorSet set = nodes[i]->validators_for(snap.height + 1);
    hyle::PubKey pk = nodes[i]->pubkey();
    malachite::Config cfg = make_cfg(malachite::Bytes(pk.begin(), pk.end()), snap.height + 1, set);
    engines[i] = std::make_unique<malachite::Engine>(cfg, *nodes[i]);
    active[i] = 1;
  }

  void join_far(int joiner, int source) {
    const hyle::Snapshot& snap = nodes[source]->stored_snapshot();
    nodes[joiner]->restore_snapshot(snap);
    malachite::ValidatorSet set = nodes[joiner]->validators_for(snap.height + 1);
    hyle::PubKey pk = nodes[joiner]->pubkey();
    malachite::Config cfg = make_cfg(malachite::Bytes(pk.begin(), pk.end()), snap.height + 1, set);
    engines[joiner] = std::make_unique<malachite::Engine>(cfg, *nodes[joiner]);
    active[joiner] = 1;
    catch_up(joiner, source);
  }

  void catch_up(int behind, int source) {
    auto blocks = nodes[source]->blocks_after(nodes[behind]->applied_height());
    for (auto& hb : blocks) {
      uint64_t h = hb.first;
      const hyle::Block& blk = hb.second;
      engines[behind]->start_height(h, nodes[behind]->validators_for(h));
      malachite::Bytes prop(blk.proposer.begin(), blk.proposer.end());
      engines[behind]->sync_value_response(malachite::BytesView(prop), malachite::BytesView(blk.value),
                                           malachite::BytesView(blk.certificate));
      if (nodes[behind]->got_sync()) {
        engines[behind]->proposed_value(nodes[behind]->sync_height(), nodes[behind]->sync_round(),
                                        malachite::Round::nil(), malachite::BytesView(prop),
                                        malachite::BytesView(blk.value), true,
                                        malachite::ValueOrigin::Sync);
        nodes[behind]->clear_sync();
      }
    }
  }
};
