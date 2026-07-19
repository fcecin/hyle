#include <boost/test/unit_test.hpp>

#include "mesh_cluster.h"
#include "sim_mesh.h"

#include <hyle/morphe/asio_mesh.h>
#include <hyle/services/bulk.h>
#include <hyle/services/ops.h>
#include <hyle/services/runtime.h>
#include <hyle/services/schema.h>
#include <hyle/services/sync.h>

#include <boost/asio/io_context.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

using namespace hyle;
using namespace hyle::services;

// The catch-up protocol driven by Runtime over a Transport: a small checkpoint pooled to a quorum,
// then the state blob and block batches streamed as whole artifacts by the BulkTransfer chunker.
// These are the tests that define chain-ness: a node behind head, or starting from zero state, must
// reach head over the wire and then validate.

namespace {

NodeOptions sync_opts(uint64_t snapshot_interval = 0) {
  NodeOptions o;
  o.block_pace_ms = 0;
  o.snapshot_interval = snapshot_interval;
  o.sync_retry_ms = 20;
  return o;
}

bool drive(const std::vector<Runtime*>& rts, const std::function<bool()>& done,
           int max_iters = 400000) {
  for (int i = 0; i < max_iters; ++i) {
    if (done()) return true;
    bool progress = false;
    for (auto* rt : rts) if (rt->pump()) progress = true;
    for (auto* rt : rts) if (rt->advance()) progress = true;
    if (!progress)
      for (auto* rt : rts) rt->fire_one_timeout();
  }
  return done();
}

// all live nodes at one height, at or past goal
bool converged(const std::vector<Runtime*>& live, uint64_t goal) {
  const uint64_t h = live[0]->height();
  if (h < goal) return false;
  for (auto* rt : live)
    if (rt->height() != h) return false;
  return true;
}

void isolate(morphe::SimMesh& mesh, const std::vector<KeyPair>& kps, size_t i) {
  for (size_t j = 0; j < kps.size(); ++j)
    if (j != i) mesh.down(kps[i].pub, kps[j].pub);
}

void rejoin(morphe::SimMesh& mesh, const std::vector<KeyPair>& kps, size_t i) {
  for (size_t j = 0; j < kps.size(); ++j)
    if (j != i) mesh.up(kps[i].pub, kps[j].pub);
}

} // namespace

BOOST_AUTO_TEST_SUITE(WireSync)

BOOST_AUTO_TEST_CASE(SyncControlCodecsRoundTrip) {
  CheckpointReq cq{7, 42};
  CheckpointReq cq2 = decode_checkpoint_req(wire::View(encode_checkpoint_req(cq)));
  BOOST_TEST(cq2.have == 7u);
  BOOST_TEST(cq2.nonce == 42u);

  BlobReq bq{1, 9, 5};
  BlobReq bq2 = decode_blob_req(wire::View(encode_blob_req(bq)));
  BOOST_TEST(bq2.kind == 1);
  BOOST_TEST(bq2.height == 9u);
  BOOST_TEST(bq2.nonce == 5u);

  std::vector<SyncBlock> blocks;
  for (uint64_t h = 8; h <= 10; ++h) {
    SyncBlock b;
    b.height = h;
    b.proposer.fill(static_cast<uint8_t>(h));
    b.value = {1, 2, 3, static_cast<uint8_t>(h)};
    b.certificate = {9, 9};
    blocks.push_back(b);
  }
  wire::Bytes enc = encode_blocks(blocks);
  std::vector<SyncBlock> dec = decode_blocks(wire::View(enc));
  BOOST_REQUIRE(dec.size() == 3u);
  BOOST_TEST(dec[2].height == 10u);
  BOOST_TEST(dec[1].value == blocks[1].value);
  BOOST_TEST(dec[0].certificate == blocks[0].certificate);
  enc.pop_back();
  BOOST_CHECK_THROW(decode_blocks(wire::View(enc)), wire::Error);
}

// The chunker moves a whole artifact across a transport that carries only small pieces and hands
// back exactly the bytes -- the property the core relies on to never see a chunk. It rides a
// reliable ordered send, so it does split/reassemble only, never retransmit or reorder.
BOOST_AUTO_TEST_CASE(BulkTransferReassemblesWholeArtifact) {
  BulkTransfer tx, rx;
  PubKey dst{}; dst.fill(0xD0);
  PubKey src{}; src.fill(0x5C);

  wire::Bytes artifact;
  for (size_t i = 0; i < 200000; ++i) artifact.push_back(static_cast<uint8_t>(i * 7 + 3));
  tx.enqueue(dst, BulkKind::StateBlob, wire::View(artifact.data(), artifact.size()));

  // 1000-byte pieces force ~200 chunks; feed each into the receiver as it is emitted.
  std::optional<BulkTransfer::Completed> done;
  int guard = 0;
  while (tx.sending() && guard++ < 100000) {
    tx.pump(1, /*piece_bytes=*/1000, [&](const PubKey&, wire::View piece) {
      if (auto d = rx.receive(src, piece)) done = std::move(d);
    });
  }
  BOOST_REQUIRE(done.has_value());
  BOOST_TEST((done->kind == BulkKind::StateBlob));
  BOOST_TEST(done->whole == artifact);

  // an empty artifact still completes (one zero-length piece).
  BulkTransfer tx2, rx2;
  tx2.enqueue(dst, BulkKind::Blocks, wire::View());
  std::optional<BulkTransfer::Completed> done2;
  tx2.pump(4, 1000, [&](const PubKey&, wire::View piece) { done2 = rx2.receive(src, piece); });
  BOOST_REQUIRE(done2.has_value());
  BOOST_TEST(done2->whole.empty());

  // a corrupt piece is dropped, not crashed.
  wire::Bytes junk = {1, 2, 3};
  BOOST_TEST(!rx2.receive(src, wire::View(junk.data(), junk.size())).has_value());
}

// The postmortem's stranded-laggard defect: a validator that missed commits must return to head
// over the wire and then be a working validator (its vote necessary for quorum).
BOOST_AUTO_TEST_CASE(LaggardRejoinsOverWireAndValidates) {
  auto kps = morphe::mesh_keys(4);
  Genesis g = morphe::mesh_genesis(kps);
  morphe::SimMesh mesh;
  std::vector<PubKey> members;
  for (auto& kp : kps) members.push_back(kp.pub);
  mesh.init(members);

  std::vector<std::unique_ptr<morphe::SimMeshPort>> ports;
  std::vector<std::unique_ptr<Runtime>> rts;
  for (int i = 0; i < 4; i++) ports.push_back(std::make_unique<morphe::SimMeshPort>(&mesh, kps[i].pub));
  for (int i = 0; i < 4; i++) rts.push_back(std::make_unique<Runtime>(g, kps[i], sync_opts(), ports[i].get()));
  std::vector<Runtime*> all{rts[0].get(), rts[1].get(), rts[2].get(), rts[3].get()};
  std::vector<Runtime*> quorum3{rts[0].get(), rts[1].get(), rts[2].get()};
  for (auto* rt : all) rt->begin();

  BOOST_REQUIRE(drive(all, [&] { return converged(all, 3); }));

  isolate(mesh, kps, 3);
  const uint64_t stranded_at = rts[3]->height();
  BOOST_REQUIRE(drive(all, [&] { return converged(quorum3, stranded_at + 5); }));
  BOOST_TEST(rts[3]->height() == stranded_at);

  rejoin(mesh, kps, 3);
  const uint64_t heal_goal = rts[0]->height() + 2;
  BOOST_REQUIRE(drive(all, [&] { return converged(all, heal_goal); }));
  Hash ref = rts[0]->node().composite_hash();
  for (auto* rt : all) BOOST_TEST((rt->node().composite_hash() == ref));

  // the healed node's vote becomes necessary: quorum is 3 of 4 and one original goes silent
  isolate(mesh, kps, 0);
  std::vector<Runtime*> with_healed{rts[1].get(), rts[2].get(), rts[3].get()};
  const uint64_t before = rts[1]->height();
  BOOST_REQUIRE(drive(all, [&] { return converged(with_healed, before + 2); }));
  ref = rts[1]->node().composite_hash();
  BOOST_TEST((rts[2]->node().composite_hash() == ref));
  BOOST_TEST((rts[3]->node().composite_hash() == ref));
}

// The postmortem's defining test: a zero-state node joins a chain whose early blocks are pruned
// (snapshot floor + tail), reaches head, is voted in, and then its vote carries the chain.
BOOST_AUTO_TEST_CASE(ZeroStateJoinerSnapshotsToHeadAndValidates) {
  auto kps = morphe::mesh_keys(5);
  std::vector<KeyPair> genesis_kps(kps.begin(), kps.begin() + 4);
  Genesis g = morphe::mesh_genesis(genesis_kps);
  morphe::SimMesh mesh;
  std::vector<PubKey> members;
  for (auto& kp : kps) members.push_back(kp.pub);
  mesh.init(members);

  std::vector<std::unique_ptr<morphe::SimMeshPort>> ports;
  std::vector<std::unique_ptr<Runtime>> rts;
  for (int i = 0; i < 4; i++) ports.push_back(std::make_unique<morphe::SimMeshPort>(&mesh, kps[i].pub));
  for (int i = 0; i < 4; i++)
    rts.push_back(std::make_unique<Runtime>(g, kps[i], sync_opts(/*snapshot_interval=*/3), ports[i].get()));
  std::vector<Runtime*> vals{rts[0].get(), rts[1].get(), rts[2].get(), rts[3].get()};
  for (auto* rt : vals) rt->begin();

  BOOST_REQUIRE(drive(vals, [&] { return converged(vals, 10); }));
  BOOST_TEST(rts[0]->node().has_snapshot());
  BOOST_TEST(rts[0]->node().snapshot_height() >= 9u);
  BOOST_TEST(rts[0]->node().oldest_block() > 1u);  // genesis tail pruned: blocks alone cannot sync

  // the joiner: same genesis, zero state, not (yet) a member
  ports.push_back(std::make_unique<morphe::SimMeshPort>(&mesh, kps[4].pub));
  rts.push_back(std::make_unique<Runtime>(g, kps[4], sync_opts(/*snapshot_interval=*/3), ports[4].get()));
  Runtime* joiner = rts[4].get();
  joiner->begin();
  std::vector<Runtime*> all{rts[0].get(), rts[1].get(), rts[2].get(), rts[3].get(), joiner};

  BOOST_REQUIRE(drive(all, [&] { return joiner->height() >= 12 && converged(all, 12); }));
  Hash ref = rts[0]->node().composite_hash();
  for (auto* rt : all) BOOST_TEST((rt->node().composite_hash() == ref));
  BOOST_TEST(!joiner->is_validator());

  // promote it; all four originals vote (governance quorum is 3 of 4)
  for (int i = 0; i < 4; i++) rts[i]->vote_add(kps[4].pub);
  BOOST_REQUIRE(drive(all, [&] {
    for (auto* rt : all) if (rt->node().member_count() != 5) return false;
    return true;
  }));
  BOOST_TEST(joiner->is_validator());
  // past the +2 schedule the joiner's power is live
  const uint64_t sched_goal = rts[0]->height() + 3;
  BOOST_REQUIRE(drive(all, [&] { return converged(all, sched_goal); }));

  // one original goes silent: quorum is 4 of 5, so the chain only commits if the joiner votes
  isolate(mesh, kps, 0);
  std::vector<Runtime*> live{rts[1].get(), rts[2].get(), rts[3].get(), joiner};
  const uint64_t before = rts[1]->height();
  BOOST_REQUIRE(drive(all, [&] { return converged(live, before + 2); }));
  ref = rts[1]->node().composite_hash();
  for (auto* rt : live) BOOST_TEST((rt->node().composite_hash() == ref));
}

// The transport invariant a post-sync joiner depends on: the engine's liveness rebroadcasts are
// byte-identical, so dedup must never suppress local delivery of consensus frames (an engine
// rebuilt by catch-up can only recover the stalled round's votes from a re-delivery). Everything
// else still delivers once.
BOOST_AUTO_TEST_CASE(SimMeshRedeliversConsensusDupes) {
  auto kps = morphe::mesh_keys(2);
  morphe::SimMesh mesh;
  mesh.init({kps[0].pub, kps[1].pub});
  morphe::SimMeshPort a(&mesh, kps[0].pub);
  morphe::SimMeshPort b(&mesh, kps[1].pub);
  int consensus = 0, tx = 0;
  b.on_recv = [&](const PubKey&, MsgType t, wire::View) {
    if (t == MsgType::Consensus) ++consensus;
    if (t == MsgType::Tx) ++tx;
  };
  wire::Bytes mc{1, 2, 3};
  wire::Bytes mt{4, 5, 6};  // distinct: the dedup id hashes (src, dest, payload), not the type
  a.send(kps[1].pub, MsgType::Consensus, Channel::Consensus, wire::View(mc.data(), mc.size()));
  a.send(kps[1].pub, MsgType::Consensus, Channel::Consensus, wire::View(mc.data(), mc.size()));
  a.send(kps[1].pub, MsgType::Tx, Channel::Mempool, wire::View(mt.data(), mt.size()));
  a.send(kps[1].pub, MsgType::Tx, Channel::Mempool, wire::View(mt.data(), mt.size()));
  BOOST_TEST(consensus == 2);
  BOOST_TEST(tx == 1);
}

BOOST_AUTO_TEST_CASE(AsioMeshRedeliversConsensusDupes) {
  boost::asio::io_context io;
  auto kps = morphe::mesh_keys(2);
  morphe::AsioMesh a(io, kps[0], /*chain_tag=*/7, /*listen_port=*/0);
  morphe::AsioMesh b(io, kps[1], 7, 0);
  a.add_peer(kps[1].pub, "127.0.0.1", b.port());
  b.add_peer(kps[0].pub, "127.0.0.1", a.port());
  int consensus = 0, tx = 0;
  b.on_recv = [&](const PubKey&, MsgType t, wire::View) {
    if (t == MsgType::Consensus) ++consensus;
    if (t == MsgType::Tx) ++tx;
  };
  a.start();
  b.start();
  for (int i = 0; i < 1000 && (a.connected() < 1 || b.connected() < 1); ++i)
    io.run_for(std::chrono::milliseconds(5));
  BOOST_REQUIRE(a.connected() >= 1);
  wire::Bytes mc{9, 9, 9};
  wire::Bytes mt{8, 8, 8};  // distinct: the dedup id hashes (src, dest, payload), not the type
  a.send(kps[1].pub, MsgType::Consensus, Channel::Consensus, wire::View(mc.data(), mc.size()));
  a.send(kps[1].pub, MsgType::Consensus, Channel::Consensus, wire::View(mc.data(), mc.size()));
  a.send(kps[1].pub, MsgType::Tx, Channel::Mempool, wire::View(mt.data(), mt.size()));
  a.send(kps[1].pub, MsgType::Tx, Channel::Mempool, wire::View(mt.data(), mt.size()));
  for (int i = 0; i < 1000 && (consensus < 2 || tx < 1); ++i)
    io.run_for(std::chrono::milliseconds(5));
  BOOST_TEST(consensus == 2);
  BOOST_TEST(tx == 1);
}

// Forged sync artifacts must not disturb a healthy node: a bad certificate is rejected by the probe
// engine before the live engine is replaced, an unsolicited state blob is dropped, and a checkpoint
// from a non-member reaches no quorum.
BOOST_AUTO_TEST_CASE(ForgedSyncArtifactsAreRejected) {
  auto kps = morphe::mesh_keys(2);
  std::vector<KeyPair> genesis_kps{kps[0]};
  Genesis g = morphe::mesh_genesis(genesis_kps);
  morphe::SimMesh mesh;
  mesh.init({kps[0].pub, kps[1].pub});

  morphe::SimMeshPort vport(&mesh, kps[0].pub);
  morphe::SimMeshPort attacker(&mesh, kps[1].pub);
  Runtime v(g, kps[0], sync_opts(), &vport);
  std::vector<Runtime*> solo{&v};
  v.begin();
  BOOST_REQUIRE(drive(solo, [&] { return v.height() >= 3; }));
  const uint64_t h0 = v.height();

  auto send_bulk = [&](BulkKind kind, wire::View whole) {
    BulkTransfer atx;
    atx.enqueue(kps[0].pub, kind, whole);
    atx.pump(64, 1u << 20, [&](const PubKey&, wire::View piece) {
      attacker.send(kps[0].pub, MsgType::BulkChunk, Channel::Bulk, piece);
    });
  };

  // a forged block batch with a garbage certificate: the probe engine rejects it, the live engine
  // is untouched, no decide-miss.
  std::vector<SyncBlock> forged;
  {
    SyncBlock b;
    b.height = h0 + 1;
    b.proposer = kps[0].pub;
    b.value = {0xDE, 0xAD};
    b.certificate = {0xBE, 0xEF};
    forged.push_back(b);
  }
  wire::Bytes fb = encode_blocks(forged);
  send_bulk(BulkKind::Blocks, wire::View(fb.data(), fb.size()));
  BOOST_TEST(v.height() == h0);
  BOOST_TEST(v.node().decide_misses() == 0u);

  // an unsolicited state blob (no quorum checkpoint pooled) is dropped outright.
  wire::Bytes junk = {1, 2, 3, 4};
  send_bulk(BulkKind::StateBlob, wire::View(junk.data(), junk.size()));
  BOOST_TEST(v.height() == h0);

  // a forged checkpoint from a non-member reaches no quorum against the trusted set.
  SnapshotCheckpoint fc;
  fc.height = 50;
  fc.app_hash.fill(0x77);
  Attestation a;
  a.height = 50;
  a.app_hash.fill(0x77);
  a.signer = kps[1].pub;
  a.sig.fill(0x11);
  fc.attestations.push_back(a);
  wire::Bytes fce = encode_checkpoint(fc);
  attacker.send(kps[0].pub, MsgType::SnapResp, Channel::Bulk, wire::View(fce.data(), fce.size()));
  BOOST_TEST(v.height() == h0);

  // the chain keeps committing; the poisoned observed head decays instead of wedging the node.
  BOOST_REQUIRE(drive(solo, [&] { return v.height() >= h0 + 3; }));
  BOOST_TEST(v.node().decide_misses() == 0u);
}

// The scale proof: with the transport capped at a small message, a zero-state joiner syncs a chain
// whose state is many messages large. The state blob and block batches cross as many small pieces
// and the chunker reassembles them to the exact committed state -- the same code Morphe runs over
// TCP and CES runs over its RUDP stream, both being nothing more than reliable ordered byte pipes.
BOOST_AUTO_TEST_CASE(MultiPieceStateBlobSyncsOverChunker) {
  auto kps = morphe::mesh_keys(5);
  std::vector<KeyPair> genesis_kps(kps.begin(), kps.begin() + 4);
  Genesis g = morphe::mesh_genesis(genesis_kps);
  g.allocations = {{kps[0].pub, 1000000000ull}};
  morphe::SimMesh mesh;
  mesh.max_message_bytes = 4096;  // force the state blob + block batches through many small pieces
  std::vector<PubKey> members;
  for (auto& kp : kps) members.push_back(kp.pub);
  mesh.init(members);

  std::vector<std::unique_ptr<morphe::SimMeshPort>> ports;
  std::vector<std::unique_ptr<Runtime>> rts;
  for (int i = 0; i < 4; i++) ports.push_back(std::make_unique<morphe::SimMeshPort>(&mesh, kps[i].pub));
  for (int i = 0; i < 4; i++)
    rts.push_back(std::make_unique<Runtime>(g, kps[i], sync_opts(/*snapshot_interval=*/3), ports[i].get()));
  std::vector<Runtime*> vals{rts[0].get(), rts[1].get(), rts[2].get(), rts[3].get()};
  for (auto* rt : vals) rt->begin();
  BOOST_REQUIRE(drive(vals, [&] { return converged(vals, 2); }));

  const wire::Bytes name = {'b', 'i', 'g'};
  const wire::Bytes payload(40 * 1024, 0xAB);  // one entry far larger than a transport message
  const wire::View chain(reinterpret_cast<const uint8_t*>(g.chain_id.data()), g.chain_id.size());
  EntryOp put = make_entry_put(kps[0], wire::View(name.data(), name.size()), 0, 0,
                               wire::View(payload.data(), payload.size()), chain);
  BOOST_REQUIRE((rts[0]->submit(put) == Admit::Ok));

  // commit it, then advance past the snapshot interval so a snapshot carries the big state and the
  // genesis tail is pruned (so a zero-state joiner MUST take the snapshot, not just blocks).
  Entry tmp;
  BOOST_REQUIRE(drive(vals, [&] {
    return rts[0]->app().entry_info(wire::View(name.data(), name.size()), tmp) && converged(vals, 12);
  }));
  BOOST_TEST(rts[0]->node().snapshot_height() >= 9u);
  BOOST_TEST(rts[0]->node().oldest_block() > 1u);

  ports.push_back(std::make_unique<morphe::SimMeshPort>(&mesh, kps[4].pub));
  rts.push_back(std::make_unique<Runtime>(g, kps[4], sync_opts(3), ports[4].get()));
  Runtime* joiner = rts[4].get();
  joiner->begin();
  std::vector<Runtime*> all{rts[0].get(), rts[1].get(), rts[2].get(), rts[3].get(), joiner};

  BOOST_REQUIRE(drive(all, [&] { return joiner->height() >= 12 && converged(all, 12); }));
  BOOST_TEST((joiner->node().composite_hash() == rts[0]->node().composite_hash()));

  // the big entry survived the multi-piece reassembly byte-for-byte.
  Entry je;
  BOOST_REQUIRE(joiner->app().entry_info(wire::View(name.data(), name.size()), je));
  BOOST_TEST(je.payload.size() == payload.size());
  BOOST_TEST((je.payload == payload));
}

// The same catch-up code proven over real TCP -- Morphe's AsioMesh. Three validators advance and
// snapshot; a follower joins over loopback sockets, streams the checkpoint, state blob and block
// tail through the chunker across real connections, and reaches the exact head. The point the
// endgame rests on: the transport is only a reliable ordered byte pipe, so what works here works
// over CES's RUDP stream unchanged.
BOOST_AUTO_TEST_CASE(JoinerSyncsOverAsioTcp) {
  boost::asio::io_context io;
  auto kps = morphe::mesh_keys(4);
  std::vector<KeyPair> genesis_kps(kps.begin(), kps.begin() + 3);
  Genesis g = morphe::mesh_genesis(genesis_kps);

  std::vector<std::unique_ptr<morphe::AsioMesh>> mesh;
  for (int i = 0; i < 4; i++)
    mesh.push_back(std::make_unique<morphe::AsioMesh>(io, kps[i], /*chain_tag=*/9, /*port=*/0));
  std::vector<std::unique_ptr<Runtime>> rts;
  for (int i = 0; i < 4; i++)
    rts.push_back(std::make_unique<Runtime>(g, kps[i], sync_opts(/*snapshot_interval=*/3), mesh[i].get()));

  auto drive_tcp = [&](std::vector<Runtime*> active, std::function<bool()> done, int max_ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(max_ms);
    int idle = 0;
    while (std::chrono::steady_clock::now() < deadline) {
      if (done()) return true;
      bool prog = false;
      for (auto* rt : active) if (rt->pump()) prog = true;
      for (auto* rt : active) if (rt->advance()) prog = true;
      io.run_for(std::chrono::milliseconds(2));
      if (!prog) { if (++idle > 40) { for (auto* rt : active) rt->fire_one_timeout(); idle = 0; } }
      else idle = 0;
    }
    return done();
  };

  // the 3 validators mesh over TCP and advance past a snapshot with a pruned genesis tail.
  for (int i = 0; i < 3; i++)
    for (int j = 0; j < 3; j++)
      if (i != j) mesh[i]->add_peer(kps[j].pub, "127.0.0.1", mesh[j]->port());
  for (int i = 0; i < 3; i++) mesh[i]->start();
  for (int i = 0; i < 3; i++) rts[i]->begin();
  std::vector<Runtime*> vals{rts[0].get(), rts[1].get(), rts[2].get()};
  BOOST_REQUIRE(drive_tcp(vals, [&] { return converged(vals, 10); }, 40000));
  BOOST_TEST(rts[0]->node().snapshot_height() >= 9u);
  BOOST_TEST(rts[0]->node().oldest_block() > 1u);

  // the follower joins over TCP.
  for (int i = 0; i < 3; i++) {
    mesh[3]->add_peer(kps[i].pub, "127.0.0.1", mesh[i]->port());
    mesh[i]->add_peer(kps[3].pub, "127.0.0.1", mesh[3]->port());
  }
  mesh[3]->start();
  rts[3]->begin();

  std::vector<Runtime*> all{rts[0].get(), rts[1].get(), rts[2].get(), rts[3].get()};
  const uint64_t goal = rts[0]->height() + 3;
  BOOST_REQUIRE(drive_tcp(all, [&] { return converged(all, goal); }, 40000));
  const Hash ref = rts[0]->node().composite_hash();
  for (auto* rt : all) BOOST_TEST((rt->node().composite_hash() == ref));
}

BOOST_AUTO_TEST_SUITE_END()
