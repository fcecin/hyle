#ifndef HYLE_SERVICES_SYNC_H
#define HYLE_SERVICES_SYNC_H

// Catch-up control messages. These are small and ride the normal channel. The big data -- the
// state blob and block batches -- rides BulkChunk (see services/bulk.h), reassembled whole before
// it reaches the node; the core only ever sees whole snapshots and whole blocks.

#include <hyle/core/crypto.h>
#include <hyle/core/wire.h>

#include <cstdint>
#include <vector>

namespace hyle::services {

// SnapReq: broadcast when behind. "I am at `have`; who can serve a snapshot above it?"
struct CheckpointReq {
  uint64_t have = 0;
  uint64_t nonce = 0;
};

// ValueReq: "stream me kind K." kind 0 = the state blob at `height`; kind 1 = the block batch
// after `height`. The reply streams back as BulkChunk pieces.
struct BlobReq {
  uint8_t kind = 0;
  uint64_t height = 0;
  uint64_t nonce = 0;
};

// One whole block inside a Blocks batch artifact.
struct SyncBlock {
  uint64_t height = 0;
  PubKey proposer{};
  wire::Bytes value;
  wire::Bytes certificate;
};

// decode_* throw wire::Error on malformed input.
wire::Bytes encode_checkpoint_req(const CheckpointReq& r);
CheckpointReq decode_checkpoint_req(wire::View v);
wire::Bytes encode_blob_req(const BlobReq& r);
BlobReq decode_blob_req(wire::View v);
wire::Bytes encode_blocks(const std::vector<SyncBlock>& blocks);
std::vector<SyncBlock> decode_blocks(wire::View v);

} // namespace hyle::services

#endif
