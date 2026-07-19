#ifndef HYLE_SERVICES_RUNTIME_H
#define HYLE_SERVICES_RUNTIME_H

#include <hyle/core/node.h>
#include <hyle/services/app.h>
#include <hyle/services/bulk.h>
#include <hyle/services/genesis.h>
#include <hyle/services/sync.h>
#include <hyle/services/transport.h>

#include <malachite/engine.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>

namespace hyle::services {

// Operational config for THIS node: how fast it paces blocks and how much history it keeps in
// RAM. Distinct from Genesis (the chain's consensus definition) -- nodes on one chain may differ.
// snapshot_interval > 0 snapshots every N blocks and drops blocks at or below the snapshot; else
// a rolling block_retention window bounds RAM.
struct NodeOptions {
  uint64_t block_pace_ms = 1000;
  // Operational overrides. Unset inherits the chain's genesis default (always a sensible value); an
  // explicit value overrides it locally. Neither enters the AppHash, so an override cannot fork.
  std::optional<uint64_t> block_retention;
  std::optional<uint64_t> snapshot_interval;
  std::string data_dir;          // vote-WAL directory ("" = in-RAM, no crash recovery)
  std::string evidence_dir;      // equivocation-evidence directory ("" = discard evidence)
  std::size_t mempool_capacity = 8192;
  uint64_t sync_retry_ms = 500;  // catch-up request retry pacing
};

class Runtime {
public:
  // The Transport outlives the Runtime.
  Runtime(const Genesis& g, const KeyPair& key, NodeOptions opts = {}, Transport* net = nullptr);

  Runtime(const Runtime&) = delete;
  Runtime& operator=(const Runtime&) = delete;
  Runtime(Runtime&&) = delete;
  Runtime& operator=(Runtime&&) = delete;

  App& app() { return app_; }
  const App& app() const { return app_; }
  hyle::Node& node() { return node_; }
  const KeyPair& key() const { return key_; }
  uint64_t height() const { return node_.applied_height(); }
  size_t peer_count() const { return net_ ? net_->peer_count() : 0; }

  Admit submit(const TransferOp& op);
  Admit submit(const EntryOp& op);
  Admit submit(const SudoOp& op);
  void regossip();

  void run_to(uint64_t goal);
  void run();
  void stop() { stop_ = true; if (on_shutdown_) on_shutdown_(); }
  void set_shutdown_hook(std::function<void()> f) { on_shutdown_ = std::move(f); }

  void begin();
  bool pump();
  bool fire_one_timeout();
  bool advance();
  void on_message(const PubKey& src, MsgType type, wire::View payload);

  // Catch-up entry point. pump() already calls it; a shell may also call it per tick. When this
  // node is behind the highest height observed from peers it requests the missing blocks
  // (ValueReq/ValueResp, certificate-verified replay) and, when the tail is pruned at every peer,
  // a snapshot (SnapReq/SnapResp, adopted on an attestation quorum). Paced by sync_retry_ms.
  void request_sync();
  uint64_t observed_height() const { return observed_head_; }

  void vote_add(const PubKey& target);
  void vote_remove(const PubKey& target);
  bool is_validator() const { return node_.is_member(key_.pub); }

  void set_evidence_dir(std::string dir) { evidence_dir_ = std::move(dir); }
  size_t evidence_count() const { return evidence_count_; }

private:
  void record_evidence(uint64_t height, int64_t round, const PubKey& proposer, const Hash& a,
                       const Hash& b);
  void maybe_sync();
  void send_blob_req(uint8_t kind, uint64_t height);
  void serve_checkpoint(const PubKey& src, wire::View payload);   // SnapReq -> CheckpointResp
  void handle_checkpoint(const PubKey& src, wire::View payload);  // SnapResp -> pool to quorum
  void serve_blob(const PubKey& src, wire::View payload);         // ValueReq -> stream via bulk
  void handle_bulk(const PubKey& src, BulkKind kind, wire::Bytes whole);  // reassembled artifact
  bool replay_blocks(const std::vector<SyncBlock>& blocks);
  static malachite::ValidatorSet make_vset(const Genesis& g);
  static malachite::Config make_engine_cfg(const KeyPair& key, uint64_t h,
                                           const malachite::ValidatorSet& vs);
  static hyle::NodeConfig make_node_cfg(const Genesis& g, const NodeOptions& opts);
  wire::View chain_v() const {
    const std::string& c = app_.chain_id();
    return wire::View(reinterpret_cast<const uint8_t*>(c.data()), c.size());
  }

  KeyPair key_;
  App app_;
  malachite::ValidatorSet vset_;
  hyle::Node node_;
  std::unique_ptr<malachite::Engine> engine_;
  Transport* net_ = nullptr;
  uint64_t pace_ms_;
  uint64_t target_ = 0;
  uint64_t started_ = 0;
  std::atomic<bool> stop_{false};
  std::function<void()> on_shutdown_;

  static constexpr uint64_t kEvidenceLookahead = 16;
  static constexpr size_t kMaxEvidencePerHeight = 256;
  std::string evidence_dir_;
  size_t evidence_count_ = 0;
  std::map<uint64_t, std::map<std::string, Hash>> proposal_seen_;

  // catch-up (wire sync). The core deals in whole artifacts; bulk_ chunks/reassembles beneath us.
  BulkTransfer bulk_;
  uint64_t observed_head_ = 0;   // highest peer height evidenced by verified Props and responses
  PubKey sync_peer_{};
  bool have_sync_peer_ = false;
  uint64_t sync_nonce_ = 0;
  std::map<Hash, SnapshotCheckpoint> ckpt_cand_;  // pooled by content key until a quorum forms
  bool have_quorum_ckpt_ = false;
  SnapshotCheckpoint quorum_ckpt_;
  std::chrono::steady_clock::time_point last_sync_req_{};
  uint64_t last_sync_applied_ = 0;
  unsigned sync_stalls_ = 0;
  uint64_t sync_retry_ms_;
};

} // namespace hyle::services

#endif
