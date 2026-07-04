#include <boost/test/unit_test.hpp>

#include "local_cluster.h"
#include "mock_state_machine.h"

#include <hyle/core/consensus.h>
#include <hyle/core/crypto.h>
#include <hyle/services/kv/ledger.h>

#include <algorithm>
#include <array>
#include <vector>

using namespace hyle;

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

BOOST_AUTO_TEST_CASE(LedgerConvergesThroughBlockSync) {
  std::vector<Ledger> led(4);
  std::vector<StateMachine*> sms;
  for (auto& x : led) sms.push_back(&x);
  LocalCluster c(sms);
  c.run_to(3, 4);
  c.deactivate(3);
  c.run_to(9, 3);
  BOOST_TEST(c.nodes[3]->last_decided() == 3u);

  c.catch_up(3, 0);
  BOOST_TEST(c.nodes[3]->last_decided() == 9u);
  BOOST_TEST(led[3].total() == led[0].total());
  BOOST_TEST(led[3].total() == 9u * Ledger::REWARD);
  BOOST_TEST((c.nodes[3]->composite_hash() == c.nodes[0]->composite_hash()));
}

BOOST_AUTO_TEST_CASE(SnapshotTakenOnCadencePrunesBlocks) {
  std::vector<MockStateMachine> sm(4);
  std::vector<StateMachine*> sms;
  for (auto& s : sm) sms.push_back(&s);
  LocalCluster c(sms, /*block_retention=*/1024, /*snapshot_interval=*/3);
  c.run(10, 4);

  for (int i = 0; i < 4; i++) {
    Node& n = *c.nodes[i];
    BOOST_TEST(n.has_snapshot());
    BOOST_TEST(n.snapshot_height() == 9u);
    BOOST_TEST(n.oldest_block() == 10u);
    BOOST_TEST(n.block_count() == 1u);
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
  BOOST_TEST(c.nodes[0]->oldest_block() == 10u);

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

BOOST_AUTO_TEST_SUITE_END()
