#include <boost/test/unit_test.hpp>

#include "local_cluster.h"
#include "mock_state_machine.h"

#include <hyle/core/consensus.h>
#include <hyle/core/crypto.h>
#include <hyle/services/app.h>

#include <algorithm>
#include <array>
#include <vector>

using namespace hyle;
using namespace hyle::services;

BOOST_AUTO_TEST_SUITE(SyncTests)

BOOST_AUTO_TEST_CASE(BlocksRetainedWithCertificates) {
  std::vector<MockStateMachine> sm(4);
  std::vector<StateMachine*> sms;
  for (auto& s : sm) sms.push_back(&s);
  LocalCluster c(sms);
  c.run(8, 4);

  for (int i = 0; i < 4; i++) {
    Node& n = *c.nodes[i];
    BOOST_TEST(n.newest_block() == 8u);
    BOOST_TEST(n.block_count() == 8u);
    for (uint64_t h = 1; h <= 8; ++h) {
      const Block* b = n.block_at(h);
      BOOST_REQUIRE(b != nullptr);
      BOOST_TEST(!b->value.empty());
      BOOST_TEST(!b->certificate.empty());
    }
  }
}

BOOST_AUTO_TEST_CASE(BlockWindowPrunes) {
  std::vector<MockStateMachine> sm(4);
  std::vector<StateMachine*> sms;
  for (auto& s : sm) sms.push_back(&s);
  LocalCluster c(sms, /*block_retention=*/3);
  c.run(10, 4);

  for (int i = 0; i < 4; i++) {
    Node& n = *c.nodes[i];
    BOOST_TEST(n.newest_block() == 10u);
    BOOST_TEST(n.block_count() == 3u);
    BOOST_TEST(n.oldest_block() == 8u);
  }
}

BOOST_AUTO_TEST_CASE(BlocksAfterReturnsTail) {
  std::vector<MockStateMachine> sm(4);
  std::vector<StateMachine*> sms;
  for (auto& s : sm) sms.push_back(&s);
  LocalCluster c(sms);
  c.run(6, 4);

  auto tail = c.nodes[0]->blocks_after(3);
  BOOST_TEST(tail.size() == 3u);
  BOOST_TEST(tail.front().first == 4u);
  BOOST_TEST(tail.back().first == 6u);
}

BOOST_AUTO_TEST_CASE(NearBehindCatchesUpViaBlocks) {
  std::vector<MockStateMachine> sm(4);
  std::vector<StateMachine*> sms;
  for (auto& s : sm) sms.push_back(&s);
  LocalCluster c(sms);
  c.run_to(3, 4);
  c.deactivate(3);
  c.run_to(8, 3);
  BOOST_TEST(c.nodes[3]->last_decided() == 3u);
  BOOST_TEST(c.nodes[0]->newest_block() == 8u);

  c.catch_up(3, 0);
  BOOST_TEST(c.nodes[3]->last_decided() == 8u);
  BOOST_TEST((c.nodes[3]->composite_hash() == c.nodes[0]->composite_hash()));
}

BOOST_AUTO_TEST_CASE(EmptyCertificateBlockNotRetained) {
  std::vector<MockStateMachine> sm(4);
  std::vector<StateMachine*> sms;
  for (auto& s : sm) sms.push_back(&s);
  LocalCluster c(sms);
  c.run(3, 4);
  Node& n = *c.nodes[0];
  n.get_value(4, malachite::Round{0}, 0);
  malachite::BytesView pv = n.proposal_value();
  Hash vid = sha256(wire::View(pv.data, pv.size));
  malachite::Decision d;
  d.height = 4;
  d.round = malachite::Round{0};
  d.value_id = malachite::BytesView(vid.data(), vid.size());
  n.decide(d);
  BOOST_TEST(n.applied_height() == 4u);
  BOOST_TEST(!n.has_block(4u));
}

BOOST_AUTO_TEST_CASE(DecideMissBecomesZombieThenBlockSyncHeals) {
  std::vector<MockStateMachine> sm(4);
  std::vector<StateMachine*> sms;
  for (auto& s : sm) sms.push_back(&s);
  LocalCluster c(sms);
  c.run_to(3, 4);
  c.deactivate(3);
  c.run_to(4, 3);
  BOOST_TEST(c.nodes[3]->applied_height() == 3u);

  std::array<uint8_t, 32> phantom;
  phantom.fill(0xAB);
  malachite::Decision miss;
  miss.height = 4;
  miss.round = malachite::Round{0};
  miss.value_id = malachite::BytesView(phantom.data(), phantom.size());
  c.nodes[3]->decide(miss);

  BOOST_TEST(c.nodes[3]->last_decided() == 4u);
  BOOST_TEST(c.nodes[3]->applied_height() == 3u);
  BOOST_TEST(c.nodes[3]->decide_misses() == 1u);
  BOOST_TEST((c.nodes[3]->composite_hash() != c.nodes[0]->composite_hash()));

  c.catch_up(3, 0);
  BOOST_TEST(c.nodes[3]->applied_height() == 4u);
  BOOST_TEST((c.nodes[3]->composite_hash() == c.nodes[0]->composite_hash()));
}

BOOST_AUTO_TEST_CASE(SnapshotTakenOnCadencePrunesBlocks) {
  std::vector<MockStateMachine> sm(4);
  std::vector<StateMachine*> sms;
  for (auto& s : sm) sms.push_back(&s);
  LocalCluster c(sms, /*block_retention=*/1024, /*snapshot_interval=*/3);
  c.run(10, 4);

  // K=2 double buffer: snapshots at 3, 6, 9; current is 9, previous is 6. Blocks are pruned only
  // above the OLDER slot (6), so 7..10 are retained -- a joiner adopting the previous snapshot at 6
  // still finds its tail.
  for (int i = 0; i < 4; i++) {
    Node& n = *c.nodes[i];
    BOOST_TEST(n.has_snapshot());
    BOOST_TEST(n.snapshot_height() == 9u);
    BOOST_TEST(n.oldest_block() == 7u);
    BOOST_TEST(n.block_count() == 4u);
  }
}

BOOST_AUTO_TEST_CASE(FarBehindJoinsViaSnapshotThenBlocks) {
  std::vector<MockStateMachine> sm(4);
  std::vector<StateMachine*> sms;
  for (auto& s : sm) sms.push_back(&s);
  LocalCluster c(sms, /*block_retention=*/1024, /*snapshot_interval=*/3);
  c.run_to(2, 4);
  c.deactivate(3);
  c.run_to(10, 3);
  BOOST_TEST(c.nodes[3]->last_decided() == 2u);
  BOOST_TEST(c.nodes[0]->snapshot_height() == 9u);
  BOOST_TEST(c.nodes[0]->oldest_block() == 7u);  // K=2: retained above the previous slot (6)

  c.join_far(3, 0);
  BOOST_TEST(c.nodes[3]->last_decided() == 10u);
  BOOST_TEST((c.nodes[3]->composite_hash() == c.nodes[0]->composite_hash()));
}

BOOST_AUTO_TEST_CASE(SyncedNodeResumesLiveValidation) {
  std::vector<MockStateMachine> sm(4);
  std::vector<StateMachine*> sms;
  for (auto& s : sm) sms.push_back(&s);
  LocalCluster c(sms, /*block_retention=*/1024, /*snapshot_interval=*/3);
  c.run_to(2, 4);
  c.deactivate(3);
  c.run_to(10, 3);
  c.join_far(3, 0);
  BOOST_TEST(c.nodes[3]->last_decided() == 10u);

  c.run_to(13, 4);
  for (int i = 0; i < 4; i++) {
    BOOST_TEST(c.nodes[i]->last_decided() == 13u);
    BOOST_TEST((c.nodes[i]->composite_hash() == c.nodes[0]->composite_hash()));
  }
}

BOOST_AUTO_TEST_CASE(NewMemberVotedInThenJoinsAndValidates) {
  std::vector<MockStateMachine> sm(5);
  std::vector<StateMachine*> sms;
  for (auto& s : sm) sms.push_back(&s);
  LocalCluster c(sms, /*block_retention=*/1024, /*snapshot_interval=*/3, /*genesis_count=*/4);

  const PubKey newk = c.nodes[4]->pubkey();
  std::array<uint8_t, 32> data{};
  std::copy(newk.begin(), newk.end(), data.begin());
  for (int i = 0; i < 4; i++)
    c.nodes[i]->submit_gov_vote(consensus::Governance::Kind::Add, newk, data);

  c.run_to(13, 4);
  BOOST_TEST(c.nodes[0]->member_count() == 5u);

  c.join_far(4, 0);
  BOOST_TEST(c.nodes[4]->last_decided() == c.nodes[0]->last_decided());
  BOOST_TEST(c.nodes[4]->member_count() == 5u);
  BOOST_TEST(c.nodes[4]->is_member(newk));
  BOOST_TEST((c.nodes[4]->composite_hash() == c.nodes[0]->composite_hash()));

  uint64_t tip = c.nodes[0]->last_decided();
  c.run_to(tip + 3, 5);
  for (int i = 0; i < 5; i++) {
    BOOST_TEST(c.nodes[i]->last_decided() == tip + 3);
    BOOST_TEST((c.nodes[i]->composite_hash() == c.nodes[0]->composite_hash()));
  }
}

// Security regression: a malicious snapshot source must not be able to install a forged validator
// set. The +1/+2 schedule is bound into the AppHash the attestations sign, so (1) the separate
// next_set fields are ignored -- the joiner uses the schedule from the hashed governance -- and
// (2) tampering the schedule inside the governance bytes fails the attestation quorum. Before the
// fix, restore_snapshot trusted snapshot.next_set, so an attacker could hand a joiner its own key
// as the height-S+1 validators and then forge every block after S onto a fork.
BOOST_AUTO_TEST_CASE(ForgedSnapshotScheduleIsNotTrusted) {
  std::vector<MockStateMachine> sm(4);
  std::vector<StateMachine*> sms;
  for (auto& s : sm) sms.push_back(&s);
  LocalCluster c(sms, /*block_retention=*/1024, /*snapshot_interval=*/3);
  c.run(9, 4);  // snapshot at height 9

  Node& honest = *c.nodes[0];
  BOOST_REQUIRE(honest.has_snapshot());
  BOOST_TEST(honest.snapshot_height() == 9u);
  const malachite::ValidatorSet real_next = honest.validators_for(10);

  Snapshot snap = honest.stored_snapshot();
  snap.attestations = {c.nodes[0]->attestation(), c.nodes[1]->attestation(),
                       c.nodes[2]->attestation()};  // 3 of 4 = quorum over the real app_hash
  const malachite::ValidatorSet trusted = c.vset;

  KeyPair attacker = KeyPair::generate();
  malachite::Validator av;
  av.address = malachite::Bytes(attacker.pub.begin(), attacker.pub.end());
  av.public_key = av.address;
  av.voting_power = 1;
  const malachite::ValidatorSet forged = {av};

  // Attack 1: forge the separate next_set fields. Adopt still succeeds (real gov/app/attestations),
  // but the joiner must end up with the REAL validator set, not the attacker's key.
  {
    Snapshot t = snap;
    t.next_set = forged;
    t.next_set2 = forged;
    MockStateMachine jsm;
    Node joiner(c.kps[0], c.vset, jsm, c.node_cfg());
    BOOST_TEST(joiner.adopt_snapshot(t, trusted));
    const malachite::ValidatorSet js = joiner.validators_for(10);
    BOOST_TEST(js.size() == real_next.size());
    bool has_attacker = false;
    for (const auto& v : js)
      if (v.public_key == av.public_key) has_attacker = true;
    BOOST_TEST(!has_attacker);  // the forged next_set had no effect
  }

  // Attack 2: forge the schedule INSIDE the hashed governance bytes (corrupt a scheduled validator
  // key). The recomputed AppHash now differs from the attested one, so the quorum fails.
  {
    Snapshot t = snap;
    BOOST_REQUIRE(t.governance.size() > 40);
    t.governance[t.governance.size() - 40] ^= 0xFF;
    MockStateMachine jsm;
    Node joiner(c.kps[0], c.vset, jsm, c.node_cfg());
    BOOST_TEST(!joiner.adopt_snapshot(t, trusted));  // schedule is bound into the AppHash
  }
}

BOOST_AUTO_TEST_SUITE_END()
