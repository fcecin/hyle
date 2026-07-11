#include <boost/test/unit_test.hpp>

#include "local_cluster.h"
#include "mock_state_machine.h"

#include <hyle/core/crypto.h>
#include <hyle/services/kv/kv_state_machine.h>
#include <hyle/core/node.h>
#include <hyle/services/kv/ops.h>
#include <hyle/core/snapshot.h>

#include <string>
#include <vector>

using namespace hyle;
using namespace hyle::services::kv;

static wire::View sv(const std::string& s) {
  return wire::View(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

struct Chain {
  std::vector<KvStateMachine> sm{std::vector<KvStateMachine>(4)};
  std::vector<StateMachine*> sms;
  std::unique_ptr<LocalCluster> c;
  std::vector<Attestation> atts;

  Chain() {
    sm[0].submit(Op::put(sv("a"), sv("1")));
    sm[1].submit(Op::put(sv("b"), sv("2")));
    sm[2].submit(Op::put(sv("c"), sv("3")));
    for (auto& s : sm) sms.push_back(&s);
    c = std::make_unique<LocalCluster>(sms);
    c->run(5, 4);
    for (int i = 0; i < 4; i++) atts.push_back(c->nodes[i]->attestation());
  }
};

BOOST_AUTO_TEST_SUITE(SnapshotTests)

BOOST_AUTO_TEST_CASE(FreshNodeAdoptsVerifiedSnapshot) {
  Chain chain;
  Snapshot snap = chain.c->nodes[0]->build_snapshot(chain.atts);
  BOOST_TEST(snap.height == 5u);

  KvStateMachine jsm;
  Node joiner(KeyPair::generate(), chain.c->vset, jsm);
  BOOST_TEST(joiner.adopt_snapshot(snap, chain.c->vset));
  BOOST_TEST(joiner.last_decided() == 5u);
  BOOST_TEST((joiner.composite_hash() == chain.c->nodes[0]->composite_hash()));
  const wire::Bytes* b = jsm.state().get(sv("b"));
  BOOST_REQUIRE(b != nullptr);
  BOOST_TEST(std::string(b->begin(), b->end()) == "2");
}

BOOST_AUTO_TEST_CASE(RejectsWithoutQuorum) {
  Chain chain;
  std::vector<Attestation> one{chain.atts[0]};
  Snapshot snap = chain.c->nodes[0]->build_snapshot(one);

  KvStateMachine jsm;
  Node joiner(KeyPair::generate(), chain.c->vset, jsm);
  BOOST_TEST(!joiner.adopt_snapshot(snap, chain.c->vset));
}

BOOST_AUTO_TEST_CASE(RejectsTamperedState) {
  Chain chain;
  Snapshot snap = chain.c->nodes[0]->build_snapshot(chain.atts);
  snap.app.push_back(0xff);

  KvStateMachine jsm;
  Node joiner(KeyPair::generate(), chain.c->vset, jsm);
  BOOST_TEST(!joiner.adopt_snapshot(snap, chain.c->vset));
}

BOOST_AUTO_TEST_CASE(RejectsAttestationsFromNonMembers) {
  Chain chain;
  Snapshot snap = chain.c->nodes[0]->build_snapshot(chain.atts);
  wire::Bytes buf = snap.governance;
  buf.insert(buf.end(), snap.app.begin(), snap.app.end());
  Hash apphash = sha256(buf);
  std::vector<Attestation> fake;
  for (int i = 0; i < 4; i++) {
    KeyPair k = KeyPair::generate();
    Attestation a;
    a.height = snap.height;
    a.app_hash = apphash;
    a.signer = k.pub;
    a.sig = k.sign(attestation_bytes(snap.height, apphash));
    fake.push_back(a);
  }
  snap.attestations = fake;

  KvStateMachine jsm;
  Node joiner(KeyPair::generate(), chain.c->vset, jsm);
  BOOST_TEST(!joiner.adopt_snapshot(snap, chain.c->vset));
}

BOOST_AUTO_TEST_CASE(QuorumBoundaryExactAtTwoThirds) {
  Chain chain;
  {
    std::vector<Attestation> two{chain.atts[0], chain.atts[1]};
    Snapshot snap = chain.c->nodes[0]->build_snapshot(two);
    KvStateMachine jsm;
    Node joiner(KeyPair::generate(), chain.c->vset, jsm);
    BOOST_TEST(!joiner.adopt_snapshot(snap, chain.c->vset));
  }
  {
    std::vector<Attestation> three{chain.atts[0], chain.atts[1], chain.atts[2]};
    Snapshot snap = chain.c->nodes[0]->build_snapshot(three);
    KvStateMachine jsm;
    Node joiner(KeyPair::generate(), chain.c->vset, jsm);
    BOOST_TEST(joiner.adopt_snapshot(snap, chain.c->vset));
  }
}

BOOST_AUTO_TEST_CASE(DuplicateSignerNotDoubleCounted) {
  Chain chain;
  std::vector<Attestation> dup{chain.atts[0], chain.atts[0], chain.atts[1]};
  Snapshot snap = chain.c->nodes[0]->build_snapshot(dup);
  KvStateMachine jsm;
  Node joiner(KeyPair::generate(), chain.c->vset, jsm);
  BOOST_TEST(!joiner.adopt_snapshot(snap, chain.c->vset));
}

BOOST_AUTO_TEST_CASE(RestoreSnapshotRejectsMalformedNotCrash) {
  Chain chain;
  Snapshot good = chain.c->nodes[0]->build_snapshot(chain.atts);

  Snapshot bad_app = good;
  bad_app.app.resize(bad_app.app.size() / 2 + 1);
  KvStateMachine jsm;
  Node j1(KeyPair::generate(), chain.c->vset, jsm);
  BOOST_TEST(!j1.restore_snapshot(bad_app));

  Snapshot bad_gov = good;
  BOOST_REQUIRE(!bad_gov.governance.empty());
  bad_gov.governance.pop_back();
  KvStateMachine jsm2;
  Node j2(KeyPair::generate(), chain.c->vset, jsm2);
  BOOST_TEST(!j2.restore_snapshot(bad_gov));

  KvStateMachine jsm3;
  Node j3(KeyPair::generate(), chain.c->vset, jsm3);
  BOOST_TEST(j3.restore_snapshot(good));
  BOOST_TEST(j3.last_decided() == 5u);
}

BOOST_AUTO_TEST_CASE(OfflineMemberRejoinsBySnapshotAndValidates) {
  std::vector<MockStateMachine> sm(4);
  std::vector<StateMachine*> sms;
  for (auto& s : sm) sms.push_back(&s);
  LocalCluster c(sms);
  c.deactivate(3);
  c.run_to(5, 3);
  BOOST_TEST(c.committed(5) == 3);
  BOOST_TEST(c.nodes[3]->last_decided() == 0u);

  std::vector<Attestation> atts{c.nodes[0]->attestation(), c.nodes[1]->attestation(),
                                c.nodes[2]->attestation()};
  Snapshot snap = c.nodes[0]->build_snapshot(atts);
  c.join(3, snap, c.vset);
  BOOST_TEST(c.nodes[3]->last_decided() == 5u);

  c.run_to(9, 4);
  BOOST_TEST(c.nodes[3]->last_decided() == 9u);
  BOOST_TEST((c.nodes[3]->composite_hash() == c.nodes[0]->composite_hash()));
}

BOOST_AUTO_TEST_CASE(AdoptSnapshotUnderChainId) {
  std::vector<KvStateMachine> sm(4);
  sm[0].submit(Op::put(sv("a"), sv("1")));
  std::vector<StateMachine*> sms;
  for (auto& s : sm) sms.push_back(&s);
  LocalCluster c(sms, 1024, 0, -1, "chain-Z");
  c.run(5, 4);
  std::vector<Attestation> atts;
  for (int i = 0; i < 4; i++) atts.push_back(c.nodes[i]->attestation());
  Snapshot snap = c.nodes[0]->build_snapshot(atts);

  KvStateMachine jsm;
  NodeConfig cfg;
  cfg.chain_id = "chain-Z";
  Node joiner(KeyPair::generate(), c.vset, jsm, cfg);
  BOOST_TEST(joiner.adopt_snapshot(snap, c.vset));
  BOOST_TEST((joiner.composite_hash() == c.nodes[0]->composite_hash()));

  KvStateMachine jsm2;
  NodeConfig cfg2;
  cfg2.chain_id = "chain-OTHER";
  Node joiner2(KeyPair::generate(), c.vset, jsm2, cfg2);
  BOOST_TEST(!joiner2.adopt_snapshot(snap, c.vset));
}

BOOST_AUTO_TEST_CASE(StraddlingGovernanceProposalConvergesOnJoin) {
  std::vector<MockStateMachine> sm(5);
  std::vector<StateMachine*> sms;
  for (auto& s : sm) sms.push_back(&s);
  LocalCluster c(sms);
  c.deactivate(4);

  KeyPair cand = KeyPair::generate();
  const PubKey e = cand.pub;
  std::array<uint8_t, 32> data{};
  std::copy(e.begin(), e.end(), data.begin());
  for (int i = 0; i < 3; i++)
    c.nodes[i]->submit_gov_vote(consensus::Governance::Kind::Add, e, data);
  c.run_to(6, 4);
  BOOST_TEST(!c.nodes[0]->is_member(e));
  BOOST_TEST(c.nodes[0]->member_count() == 5u);

  std::vector<Attestation> atts;
  for (int i = 0; i < 4; i++) atts.push_back(c.nodes[i]->attestation());
  Snapshot snap = c.nodes[0]->build_snapshot(atts);
  c.join(4, snap, c.vset);
  BOOST_TEST(c.nodes[4]->last_decided() == 6u);

  c.nodes[3]->submit_gov_vote(consensus::Governance::Kind::Add, e, data);
  c.run_to(12, 5);
  for (int i = 0; i < 5; i++) {
    BOOST_TEST(c.nodes[i]->is_member(e));
    BOOST_TEST(c.nodes[i]->member_count() == 6u);
  }
  BOOST_TEST((c.nodes[4]->composite_hash() == c.nodes[0]->composite_hash()));
}

BOOST_AUTO_TEST_CASE(SnapshotCarriesInFlightScheduleChange) {
  std::vector<MockStateMachine> sm(4);
  std::vector<StateMachine*> sms;
  for (auto& s : sm) sms.push_back(&s);
  LocalCluster c(sms);

  KeyPair cand = KeyPair::generate();
  const PubKey e = cand.pub;
  std::array<uint8_t, 32> data{};
  std::copy(e.begin(), e.end(), data.begin());
  for (int i = 0; i < 3; i++)
    c.nodes[i]->submit_gov_vote(consensus::Governance::Kind::Add, e, data);
  uint64_t hs = 0;
  for (uint64_t h = 1; h <= 8 && hs == 0; ++h) {
    c.run_to(h, 4);
    if (c.nodes[0]->member_count() == 5u) hs = c.nodes[0]->last_decided();
  }
  BOOST_REQUIRE(hs != 0u);
  BOOST_REQUIRE(c.nodes[0]->validators_for(hs + 1).size() == 4u);
  BOOST_REQUIRE(c.nodes[0]->validators_for(hs + 2).size() == 5u);

  std::vector<Attestation> atts;
  for (int i = 0; i < 4; i++) atts.push_back(c.nodes[i]->attestation());
  Snapshot snap = c.nodes[0]->build_snapshot(atts);
  MockStateMachine jsm;
  Node joiner(KeyPair::generate(), c.vset, jsm);
  BOOST_TEST(joiner.restore_snapshot(snap));
  BOOST_TEST(joiner.validators_for(hs + 1).size() == 4u);
  BOOST_TEST(joiner.validators_for(hs + 2).size() == 5u);
}

BOOST_AUTO_TEST_SUITE_END()
