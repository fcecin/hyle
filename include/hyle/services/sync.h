#ifndef HYLE_SERVICES_SYNC_H
#define HYLE_SERVICES_SYNC_H

// Wire codecs for the catch-up protocol (ValueReq/ValueResp, SnapReq/SnapResp).
// Runtime drives it over the Transport seam: a behind node requests, a node at
// head serves its retained blocks and stored snapshot.

#include <hyle/core/crypto.h>
#include <hyle/core/snapshot.h>
#include <hyle/core/wire.h>

#include <cstdint>
#include <vector>

namespace hyle::services {

struct SyncBlock {
  uint64_t height = 0;
  PubKey proposer{};
  wire::Bytes value;
  wire::Bytes certificate;
};

// ValueReq: send me the blocks after `from`. `nonce` varies per attempt so
// transport dedup caches do not swallow retries.
struct SyncBlocksReq {
  uint64_t from = 0;
  uint64_t nonce = 0;
};

// ValueResp: `head` is the server's applied height. Empty `blocks` with
// head above the requested `from` means the tail is pruned: fetch a snapshot.
struct SyncBlocksResp {
  uint64_t nonce = 0;
  uint64_t head = 0;
  std::vector<SyncBlock> blocks;
};

// SnapReq: serve your stored snapshot if its height is above `have`.
struct SyncSnapReq {
  uint64_t have = 0;
  uint64_t nonce = 0;
};

struct SyncSnapResp {
  uint64_t nonce = 0;
  Snapshot snap;
};

// decode_* throw wire::Error on malformed input.
wire::Bytes encode_sync_blocks_req(const SyncBlocksReq& r);
SyncBlocksReq decode_sync_blocks_req(wire::View v);
wire::Bytes encode_sync_blocks_resp(const SyncBlocksResp& r);
SyncBlocksResp decode_sync_blocks_resp(wire::View v);
wire::Bytes encode_sync_snap_req(const SyncSnapReq& r);
SyncSnapReq decode_sync_snap_req(wire::View v);
wire::Bytes encode_sync_snap_resp(const SyncSnapResp& r);
SyncSnapResp decode_sync_snap_resp(wire::View v);

// Hash of the snapshot minus its attestations: groups candidates by content so
// attestations from many servers merge toward one adoption quorum.
Hash snapshot_content_key(const Snapshot& s);

} // namespace hyle::services

#endif
