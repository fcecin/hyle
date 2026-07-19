#ifndef HYLE_SERVICES_GENESIS_H
#define HYLE_SERVICES_GENESIS_H

#include <hyle/core/crypto.h>
#include <hyle/core/wire.h>
#include <hyle/services/config.h>

#include <string>
#include <utility>
#include <vector>

namespace hyle::services {

struct Genesis {
  std::string chain_id;
  std::vector<PubKey> validators;
  std::vector<std::pair<PubKey, uint64_t>> allocations;
  Config config;

  // Network-agreed defaults for the operational sync window: every node starts from the same sane
  // baseline (a too-small window makes a node un-syncable). They ride the genesis but are NOT
  // consensus -- they never enter the per-height AppHash, so a node may override them locally
  // (NodeOptions) without forking. default_snapshot_interval is in blocks (0 = snapshots off; the
  // chain then syncs from the block window alone); default_block_retention is that rolling window,
  // used when snapshots are off.
  uint64_t default_snapshot_interval = 0;
  uint64_t default_block_retention = 1024;

  wire::Bytes canonical() const;
  Hash hash() const;

  bool validate(std::string& err) const;

  static Genesis parse(const std::string& text);
  std::string to_text() const;
};

} // namespace hyle::services

#endif
