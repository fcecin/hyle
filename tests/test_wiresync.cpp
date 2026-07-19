#include <boost/test/unit_test.hpp>

#include "mesh_cluster.h"
#include "sim_mesh.h"

#include <hyle/morphe/asio_mesh.h>
#include <hyle/services/runtime.h>
#include <hyle/services/sync.h>

#include <boost/asio/io_context.hpp>

#include <chrono>
#include <functional>
#include <memory>
#include <vector>

using namespace hyle;
using namespace hyle::services;

// The catch-up wire protocol (ValueReq/ValueResp, SnapReq/SnapResp) driven by Runtime over a
// Transport. These are the tests that define chain-ness: a node behind head, or starting from
// zero state, must reach head over the wire and then validate.

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

BOOST_AUTO_TEST_CASE(SyncCodecRoundTrips) {
  SyncBlocksReq breq{7, 42};
  SyncBlocksReq breq2 = decode_sync_blocks_req(wire::View(encode_sync_blocks_req(breq)));
  BOOST_TEST(breq2.from == 7u);
  BOOST_TEST(breq2.nonce == 42u);

  SyncBlocksResp bresp;
  bresp.nonce = 42;
  bresp.head = 9;
  for (uint64_t h = 8; h <= 9; ++h) {
    SyncBlock b;
    b.height = h;
    b.proposer.fill(static_cast<uint8_t>(h));
    b.value = {1, 2, 3, static_cast<uint8_t>(h)};
    b.certificate = {9, 9};
    bresp.blocks.push_back(b);
  }
  wire::Bytes enc = encode_sync_blocks_resp(bresp);
  SyncBlocksResp bresp2 = decode_sync_blocks_resp(wire::View(enc));
  BOOST_TEST(bresp2.head == 9u);
  BOOST_REQUIRE(bresp2.blocks.size() == 2u);
  BOOST_TEST(bresp2.blocks[1].height == 9u);
  BOOST_TEST(bresp2.blocks[1].value == bresp.blocks[1].value);
  BOOST_TEST(bresp2.blocks[0].certificate == bresp.blocks[0].certificate);
  enc.pop_back();
  BOOST_CHECK_THROW(decode_sync_blocks_resp(wire::View(enc)), wire::Error);

  SyncSnapReq sreq{3, 1};
  SyncSnapReq sreq2 = decode_sync_snap_req(wire::View(encode_sync_snap_req(sreq)));
  BOOST_TEST(sreq2.have == 3u);

  SyncSnapResp sresp;
  sresp.nonce = 5;
  sresp.snap.height = 12;
  sresp.snap.governance = {4, 5, 6};
  sresp.snap.app = {7, 8};
  malachite::Validator v;
  v.public_key.assign(32, 0xAA);
  v.address = v.public_key;
  v.voting_power = 1;
  sresp.snap.next_set.push_back(v);
  sresp.snap.next_set2.push_back(v);
  Attestation a;
  a.height = 12;
  a.app_hash.fill(1);
  a.signer.fill(2);
  a.sig.fill(3);
  sresp.snap.attestations.push_back(a);
  wire::Bytes senc = encode_sync_snap_resp(sresp);
  SyncSnapResp sresp2 = decode_sync_snap_resp(wire::View(senc));
  BOOST_TEST(sresp2.snap.height == 12u);
  BOOST_TEST(sresp2.snap.governance == sresp.snap.governance);
  BOOST_REQUIRE(sresp2.snap.next_set.size() == 1u);
  BOOST_TEST(sresp2.snap.next_set[0].public_key == v.public_key);
  BOOST_REQUIRE(sresp2.snap.attestations.size() == 1u);
  BOOST_TEST((sresp2.snap.attestations[0].signer == a.signer));
  senc.pop_back();
  BOOST_CHECK_THROW(decode_sync_snap_resp(wire::View(senc)), wire::Error);

  // the content key ignores attestations: candidates from many servers pool
  Snapshot bare = sresp.snap;
  bare.attestations.clear();
  BOOST_TEST((snapshot_content_key(bare) == snapshot_content_key(sresp.snap)));
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

// Forged sync responses must not disturb a healthy node: a bad certificate is rejected by the
// probe engine before the live engine is replaced, and an unsolicited snapshot is ignored.
BOOST_AUTO_TEST_CASE(ForgedSyncResponsesAreRejected) {
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

  // a fabricated next block with a garbage certificate, claiming a far head
  SyncBlocksResp forged;
  forged.nonce = 1;
  forged.head = 100;
  SyncBlock fb;
  fb.height = h0 + 1;
  fb.proposer = kps[0].pub;
  fb.value = {0xDE, 0xAD};
  fb.certificate = {0xBE, 0xEF};
  forged.blocks.push_back(fb);
  wire::Bytes fenc = encode_sync_blocks_resp(forged);
  attacker.send(kps[0].pub, MsgType::ValueResp, Channel::Bulk, wire::View(fenc.data(), fenc.size()));
  BOOST_TEST(v.height() == h0);  // not applied
  BOOST_TEST(v.node().decide_misses() == 0u);

  // an unsolicited snapshot response is dropped outright
  SyncSnapResp fsnap;
  fsnap.nonce = 2;
  fsnap.snap.height = 50;
  fsnap.snap.governance = {1};
  fsnap.snap.app = {2};
  wire::Bytes senc = encode_sync_snap_resp(fsnap);
  attacker.send(kps[0].pub, MsgType::SnapResp, Channel::Bulk, wire::View(senc.data(), senc.size()));
  BOOST_TEST(v.height() == h0);

  // the chain keeps committing; the poisoned observed head decays instead of wedging the node
  BOOST_REQUIRE(drive(solo, [&] { return v.height() >= h0 + 3; }));
  BOOST_TEST(v.node().decide_misses() == 0u);
}

BOOST_AUTO_TEST_SUITE_END()
