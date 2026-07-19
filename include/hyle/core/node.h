#ifndef HYLE_NODE_H
#define HYLE_NODE_H

// value envelope: [parent AppHash 32][u32 n_gov][n_gov governance ops][opaque app payload]

#include <hyle/core/consensus.h>
#include <hyle/core/crypto.h>
#include <hyle/core/snapshot.h>
#include <hyle/core/state_machine.h>
#include <hyle/core/wire.h>

#include <malachite/engine.hpp>

#include <boost/container_hash/hash.hpp>
#include <boost/unordered/unordered_flat_map.hpp>

#include <array>
#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace hyle {

struct Timer {
  malachite::TimeoutKind kind = malachite::TimeoutKind::Propose;
  int64_t round = -1;
  uint64_t dur = 0;
};

struct GovOp {
  consensus::Governance::Kind kind = consensus::Governance::Kind::Add;
  PubKey voter{};
  PubKey target{};
  std::array<uint8_t, 32> data{};
  Sig sig{};
};

struct Block {
  PubKey proposer{};
  wire::Bytes value;
  wire::Bytes certificate;
};

struct NodeConfig {
  unsigned member_cap = 21;
  unsigned member_floor = 1;
  uint64_t block_retention = 1024;
  uint64_t snapshot_interval = 0;
  std::string chain_id;
  uint64_t max_value_bytes = 4u << 20;
  std::string data_dir;
};

class Node : public malachite::Application {
public:
  Node(KeyPair kp, malachite::ValidatorSet vset, StateMachine& sm, const NodeConfig& config = {});
  ~Node() override;

  malachite::Bytes sign(malachite::BytesView m) override;
  bool verify(malachite::BytesView m, malachite::BytesView pk, malachite::BytesView sig) override;
  bool validate(malachite::BytesView value) override;
  void publish(PublishKind kind, malachite::BytesView m) override;
  void schedule_timeout(malachite::Timeout t, uint64_t dur) override;
  void cancel_timeout(malachite::Timeout t) override;
  void cancel_all_timeouts() override;
  void reset_timeouts() override;
  void get_value(malachite::Height h, malachite::Round r, uint64_t timeout_ms) override;
  void restream_proposal(malachite::Height, malachite::Round, malachite::Round,
                         malachite::BytesView, malachite::BytesView) override {}
  void start_round(malachite::Height, malachite::Round, malachite::BytesView,
                   malachite::Role) override;
  void decide(const malachite::Decision& d) override;
  bool get_validator_set(malachite::Height h, malachite::ValidatorSet& out) override;
  void sync_value(malachite::Height h, malachite::Round r, malachite::BytesView proposer,
                  malachite::BytesView value) override;
  void on_error(ErrorCode code, malachite::BytesView message) override;
  void wal_append(malachite::BytesView entry) override;

  void submit_gov_vote(consensus::Governance::Kind kind, const PubKey& target,
                       const std::array<uint8_t, 32>& data = {});

  Hash composite_hash() const;
  size_t member_count() const { return gov_.size(); }
  bool is_member(const PubKey& k) const;
  malachite::ValidatorSet validators_for(malachite::Height h) const;

  const Attestation& attestation() const { return last_att_; }
  Snapshot build_snapshot(std::vector<Attestation> attestations) const;
  // returns false without mutating on failure
  bool adopt_snapshot(const Snapshot& s, const malachite::ValidatorSet& trusted);
  // raw restore without verification; prefer adopt_snapshot
  bool restore_snapshot(const Snapshot& s);

  // Wire sync, split so it scales to gigabyte state (see core/snapshot.h). The core deals only in
  // whole RAM artifacts; a transport moves the small checkpoint (pooled to a quorum) and streams
  // the big state blob, and never chunks anything the core hands it.
  //
  // Serve side: the newest servable checkpoint, and the state blob for a given height. Two slots
  // are kept (K=2 double buffer): the newest a fresh request adopts, plus the previous, so a peer
  // that started a download before a fresh snapshot rotated in still finds its blob. Both hold
  // through the wall-clock a transfer needs; a straggler that outlasts even the previous slot
  // restarts. `state_blob_for` matches either slot by height. Spans are valid until the next
  // snapshot rotates a slot; copy if held across a commit.
  const SnapshotCheckpoint* servable_checkpoint() const;
  bool state_blob_for(uint64_t height, wire::View& out_blob, Hash& out_hash) const;

  // Request side: adopt a streamed state blob against a checkpoint whose attestation quorum the
  // caller has already pooled and verified (checkpoint_has_quorum, core/snapshot.h). Re-verifies
  // the quorum, then that hash(chain_id ++ gov ++ app) equals the checkpoint app_hash, then
  // restores. Returns false without mutating on any mismatch.
  bool adopt_state_blob(const SnapshotCheckpoint& c, wire::View state_blob,
                        const malachite::ValidatorSet& trusted);

  size_t block_count() const { return blocks_.size(); }
  uint64_t oldest_block() const { return blocks_.empty() ? 0 : blocks_.begin()->first; }
  uint64_t newest_block() const { return blocks_.empty() ? 0 : blocks_.rbegin()->first; }
  bool has_block(uint64_t h) const { return blocks_.count(h) != 0; }
  const Block* block_at(uint64_t h) const {
    auto it = blocks_.find(h);
    return it == blocks_.end() ? nullptr : &it->second;
  }
  bool has_snapshot() const { return snap_cur_ >= 0 && snaps_[snap_cur_].valid; }
  uint64_t snapshot_height() const { return has_snapshot() ? snaps_[snap_cur_].height : 0; }
  // Reconstructs the newest snapshot from its slot (decodes the state blob). Convenience for
  // in-process callers/tests; the wire path uses servable_checkpoint + state_blob_for.
  Snapshot stored_snapshot() const;

  std::vector<std::pair<uint64_t, Block>> blocks_after(uint64_t from) const {
    std::vector<std::pair<uint64_t, Block>> out;
    for (auto it = blocks_.upper_bound(from); it != blocks_.end(); ++it)
      out.emplace_back(it->first, it->second);
    return out;
  }

  const PubKey& pubkey() const { return kp_.pub; }
  bool wants_propose() const { return want_propose_; }
  malachite::Height proposal_height() const { return ph_; }
  malachite::Round proposal_round() const { return pr_; }
  malachite::BytesView proposal_value() const { return malachite::BytesView(pending_value_); }
  void clear_proposal() { want_propose_ = false; }
  bool accept_proposed(malachite::BytesView value);
  std::vector<malachite::Bytes> drain_outbox();
  const std::vector<Timer>& timers() const { return timers_; }
  Timer take_timer(size_t idx);
  uint64_t last_decided() const { return last_decided_; }
  // Highest contiguous height applied. A decide-miss leaves this < last_decided().
  uint64_t applied_height() const { return applied_height_; }
  size_t decide_misses() const { return decide_misses_; }
  size_t value_cache_size() const { return value_cache_.size(); }

  bool got_sync() const { return got_sync_; }
  malachite::Height sync_height() const { return sync_h_; }
  malachite::Round sync_round() const { return sync_r_; }
  malachite::BytesView sync_value_view() const { return malachite::BytesView(sync_value_); }
  void clear_sync() { got_sync_ = false; }

  bool has_boot_wal() const { return !boot_wal_.empty(); }
  const std::vector<malachite::Bytes>& boot_wal() const { return boot_wal_; }
  void begin_wal_replay() { wal_replaying_ = true; }
  void end_wal_replay() {
    wal_replaying_ = false;
    boot_wal_.clear();
  }

private:
  void cache_value(malachite::BytesView value);
  wire::Bytes governance_canonical() const;
  // split_envelope throws wire::Error on malformation.
  wire::Bytes build_envelope(const Hash& parent, const std::vector<GovOp>& gov,
                             wire::View payload) const;
  struct Envelope {
    Hash parent{};
    std::vector<GovOp> gov;
    wire::Bytes payload;
  };
  Envelope split_envelope(wire::View value) const;
  bool validate_gov(const std::vector<GovOp>& gov) const;
  void apply_gov(uint64_t height, const std::vector<GovOp>& gov);

  KeyPair kp_;
  StateMachine& sm_;
  wire::Bytes chain_id_;
  uint64_t max_value_bytes_;
  unsigned cap_;
  unsigned floor_;
  consensus::Governance gov_;
  consensus::ValidatorSetSchedule sched_;
  Attestation last_att_;
  boost::unordered_flat_map<Hash, wire::Bytes, boost::hash<Hash>> value_cache_;
  std::deque<Hash> cache_order_;
  size_t cache_bytes_ = 0;
  boost::unordered_flat_map<std::pair<uint64_t, int64_t>, PubKey,
                            boost::hash<std::pair<uint64_t, int64_t>>>
      proposers_;  // (height, round) -> proposer
  std::vector<GovOp> pending_gov_;
  std::map<uint64_t, Block> blocks_;
  uint64_t block_retention_;
  uint64_t snapshot_interval_;

  // K=2 snapshot double buffer. Each slot holds the small checkpoint plus the materialized state
  // blob (gov ++ app) serialized once at capture, so serving is a span, not a re-serialize.
  struct SnapSlot {
    bool valid = false;
    uint64_t height = 0;
    SnapshotCheckpoint checkpoint;
    wire::Bytes blob;
    Hash blob_hash{};
  };
  SnapSlot snaps_[2];
  int snap_cur_ = -1;  // newest valid slot; the other is the previous
  void take_snapshot(uint64_t height);
  uint64_t oldest_snapshot_height() const;

  bool want_propose_ = false;
  malachite::Height ph_ = 0;
  malachite::Round pr_;
  wire::Bytes pending_value_;

  std::vector<malachite::Bytes> outbox_;
  std::vector<Timer> timers_;
  uint64_t last_decided_ = 0;
  uint64_t applied_height_ = 0;
  size_t decide_misses_ = 0;

  mutable Hash composite_cache_{};
  mutable bool composite_dirty_ = true;

  bool got_sync_ = false;
  malachite::Height sync_h_ = 0;
  malachite::Round sync_r_;
  wire::Bytes sync_value_;

  int wal_fd_ = -1;
  bool wal_replaying_ = false;
  std::vector<malachite::Bytes> boot_wal_;
};

} // namespace hyle

#endif
