#include <boost/test/unit_test.hpp>

#include "local_cluster.h"

#include <hyle/core/crypto.h>
#include <hyle/services/kv/ledger.h>
#include <hyle/services/kv/pow.h>

#include <vector>

using namespace hyle;

namespace {

MintConfig cfg(unsigned min_diff, uint64_t capacity = 1000, uint64_t reward_base = 1) {
  MintConfig m;
  m.enabled = true;
  m.min_diff = min_diff;
  m.capacity = capacity;
  m.reward_base = reward_base;
  return m;
}

void apply_block(Ledger& l, uint64_t height, const MintOp& op) {
  l.submit_mint(op);
  l.apply_payload(ApplyContext{height, PubKey{}}, l.build_payload(height));
}

} // namespace

BOOST_AUTO_TEST_SUITE(MintTests)

BOOST_AUTO_TEST_CASE(RewardIsPubcomLinear) {
  Ledger l(0, cfg(8, 1000, 3));
  BOOST_TEST(l.mint_reward(1) == 3u);
  BOOST_TEST(l.mint_reward(2) == 6u);
  BOOST_TEST(l.mint_reward(9) == (uint64_t(1) << 8) * 3u);
  for (unsigned d = 1; d < 20; ++d) BOOST_TEST(l.mint_reward(d + 1) == 2 * l.mint_reward(d));
  BOOST_TEST(l.mint_reward(0) == 0u);
}

BOOST_AUTO_TEST_CASE(MintsRewardToBeneficiary) {
  Ledger l(0, cfg(8));
  Sha256PowVerifier v;
  KeyPair X = KeyPair::generate();
  MintOp op = Ledger::make_mint(v, l.mint_key(), X.pub, 8);
  unsigned d = pow_difficulty(op.solution);
  apply_block(l, 1, op);
  BOOST_TEST(l.balance(X.pub) == l.mint_reward(d));
  BOOST_TEST(l.total() == l.mint_reward(d));
  BOOST_TEST(l.mint_fill() == 1u);
  BOOST_TEST(l.mint_seen_count() == 1u);
}

BOOST_AUTO_TEST_CASE(ForgedBeneficiaryRejected) {
  Ledger l(0, cfg(8));
  Sha256PowVerifier v;
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  MintOp op = Ledger::make_mint(v, l.mint_key(), A.pub, 8);
  op.beneficiary = B.pub;
  apply_block(l, 1, op);
  BOOST_TEST(l.balance(A.pub) == 0u);
  BOOST_TEST(l.balance(B.pub) == 0u);
  BOOST_TEST(l.mint_fill() == 0u);
}

BOOST_AUTO_TEST_CASE(ReplayRejected) {
  Ledger l(0, cfg(8));
  Sha256PowVerifier v;
  KeyPair X = KeyPair::generate();
  MintOp op = Ledger::make_mint(v, l.mint_key(), X.pub, 8);
  unsigned d = pow_difficulty(op.solution);
  apply_block(l, 1, op);
  apply_block(l, 2, op);
  BOOST_TEST(l.balance(X.pub) == l.mint_reward(d));
  BOOST_TEST(l.mint_fill() == 1u);
  BOOST_TEST(l.mint_seen_count() == 1u);
}

BOOST_AUTO_TEST_CASE(BelowFloorRejected) {
  Ledger l(0, cfg(200));
  Sha256PowVerifier v;
  KeyPair X = KeyPair::generate();
  MintOp op = Ledger::make_mint(v, l.mint_key(), X.pub, 4);
  BOOST_REQUIRE(pow_difficulty(op.solution) < 200u);
  apply_block(l, 1, op);
  BOOST_TEST(l.balance(X.pub) == 0u);
  BOOST_TEST(l.mint_fill() == 0u);
}

BOOST_AUTO_TEST_CASE(CapacityRotatesFlushesAndInvalidatesOldKey) {
  Ledger l(0, cfg(6, /*capacity=*/2));
  Sha256PowVerifier v;
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  Hash key0 = l.mint_key();

  MintOp o1 = Ledger::make_mint(v, key0, A.pub, 6);
  MintOp o2 = Ledger::make_mint(v, key0, B.pub, 6);
  l.submit_mint(o1);
  l.submit_mint(o2);
  l.apply_payload(ApplyContext{1, PubKey{}}, l.build_payload(1));

  BOOST_TEST(l.mint_fill() == 0u);
  BOOST_TEST(l.mint_seen_count() == 0u);
  BOOST_TEST(!(l.mint_key() == key0));
  BOOST_TEST(l.balance(A.pub) == l.mint_reward(pow_difficulty(o1.solution)));
  BOOST_TEST(l.balance(B.pub) == l.mint_reward(pow_difficulty(o2.solution)));

  KeyPair C = KeyPair::generate();
  MintOp old = Ledger::make_mint(v, key0, C.pub, 6);
  apply_block(l, 2, old);
  BOOST_TEST(l.balance(C.pub) == 0u);

  MintOp fresh = Ledger::make_mint(v, l.mint_key(), C.pub, 6);
  unsigned d = pow_difficulty(fresh.solution);
  apply_block(l, 3, fresh);
  BOOST_TEST(l.balance(C.pub) == l.mint_reward(d));
  BOOST_TEST(l.mint_fill() == 1u);
}

BOOST_AUTO_TEST_CASE(DisabledIsNoOp) {
  Ledger l;
  BOOST_TEST(!l.mint_enabled());
  Sha256PowVerifier v;
  KeyPair X = KeyPair::generate();
  MintOp op = Ledger::make_mint(v, l.mint_key(), X.pub, 8);
  apply_block(l, 1, op);
  BOOST_TEST(l.balance(X.pub) == 0u);
  BOOST_TEST(l.total() == 0u);

  Ledger a;
  Ledger b;
  b.submit_mint(op);
  BOOST_TEST((a.build_payload(9) == b.build_payload(9)));
}

BOOST_AUTO_TEST_CASE(SnapshotRoundTripPreservesEpoch) {
  Ledger l(0, cfg(6, /*capacity=*/1000));
  Sha256PowVerifier v;
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  apply_block(l, 1, Ledger::make_mint(v, l.mint_key(), A.pub, 6));
  MintOp ob = Ledger::make_mint(v, l.mint_key(), B.pub, 6);
  apply_block(l, 2, ob);

  Ledger restored(0, cfg(6, 1000));
  restored.restore(wire::View(l.snapshot()));

  BOOST_TEST((restored.mint_key() == l.mint_key()));
  BOOST_TEST(restored.mint_fill() == l.mint_fill());
  BOOST_TEST(restored.mint_seen_count() == l.mint_seen_count());
  BOOST_TEST(restored.balance(A.pub) == l.balance(A.pub));
  uint64_t before = restored.balance(B.pub);
  apply_block(restored, 3, ob);
  BOOST_TEST(restored.balance(B.pub) == before);
}

BOOST_AUTO_TEST_CASE(TwoReplicasConvergeIncludingRotation) {
  Ledger a(0, cfg(5, /*capacity=*/3));
  Ledger b(0, cfg(5, /*capacity=*/3));
  Sha256PowVerifier v;
  std::vector<KeyPair> ks;
  for (int i = 0; i < 5; ++i) ks.push_back(KeyPair::generate());

  for (int i = 0; i < 5; ++i) {
    MintOp oa = Ledger::make_mint(v, a.mint_key(), ks[i].pub, 5);
    MintOp ob = Ledger::make_mint(v, b.mint_key(), ks[i].pub, 5);
    apply_block(a, i + 1, oa);
    apply_block(b, i + 1, ob);
  }
  BOOST_TEST(a.mint_fill() == 2u);
  BOOST_TEST((a.snapshot() == b.snapshot()));
  BOOST_TEST((a.mint_key() == b.mint_key()));
  BOOST_TEST(!(a.mint_key() == Hash{}));
}

BOOST_AUTO_TEST_CASE(MultiNodeMintConverges) {
  MintConfig mc = cfg(8, /*capacity=*/1000);
  std::vector<Ledger> led;
  led.reserve(4);
  for (int i = 0; i < 4; ++i) led.emplace_back(0, mc);
  std::vector<StateMachine*> sms;
  for (auto& x : led) sms.push_back(&x);

  Sha256PowVerifier v;
  KeyPair X = KeyPair::generate();
  Hash key0{};
  MintOp op = Ledger::make_mint(v, key0, X.pub, 8);
  unsigned d = pow_difficulty(op.solution);
  for (auto& x : led) x.submit_mint(op);

  LocalCluster c(sms);
  c.run(8, 4);

  Hash h0 = c.nodes[0]->composite_hash();
  for (int i = 1; i < 4; ++i) BOOST_TEST((c.nodes[i]->composite_hash() == h0));
  for (int i = 0; i < 4; ++i) {
    BOOST_TEST(led[i].balance(X.pub) == led[i].mint_reward(d));
    BOOST_TEST(led[i].mint_seen_count() == 1u);
  }
  for (int i = 0; i < 4; ++i)
    BOOST_TEST(led[i].total() == 8 * Ledger::REWARD + led[i].mint_reward(d));
}

BOOST_AUTO_TEST_CASE(DuplicateMintInSameBlockCreditsOnce) {
  Ledger l(0, cfg(8));
  Sha256PowVerifier v;
  KeyPair X = KeyPair::generate();
  MintOp op = Ledger::make_mint(v, l.mint_key(), X.pub, 8);
  unsigned d = pow_difficulty(op.solution);
  l.submit_mint(op);
  l.submit_mint(op);
  l.apply_payload(ApplyContext{1, PubKey{}}, l.build_payload(1));
  BOOST_TEST(l.balance(X.pub) == l.mint_reward(d));
  BOOST_TEST(l.mint_seen_count() == 1u);
  BOOST_TEST(l.mint_fill() == 1u);
}

BOOST_AUTO_TEST_CASE(MintCreditMatchesIndependentFormula) {
  Ledger l(0, cfg(8, 1000, /*reward_base=*/1));
  Sha256PowVerifier v;
  KeyPair X = KeyPair::generate();
  MintOp op = Ledger::make_mint(v, l.mint_key(), X.pub, 8);
  unsigned d = pow_difficulty(op.solution);
  BOOST_REQUIRE(d >= 8u && d <= Ledger::MINT_REWARD_MAX_DIFF);
  apply_block(l, 1, op);
  uint64_t expected = (uint64_t(1) << (d - 1));
  BOOST_TEST(l.balance(X.pub) == expected);
  BOOST_TEST(l.balance(X.pub) > 0u);
}

BOOST_AUTO_TEST_CASE(RewardCapAndSaturation) {
  Ledger l(0, cfg(8, 1000, /*reward_base=*/1));
  BOOST_TEST(l.mint_reward(Ledger::MINT_REWARD_MAX_DIFF + 1) ==
             l.mint_reward(Ledger::MINT_REWARD_MAX_DIFF));
  BOOST_TEST(l.mint_reward(200) == l.mint_reward(Ledger::MINT_REWARD_MAX_DIFF));
  Ledger big(0, cfg(8, 1000, /*reward_base=*/UINT64_MAX));
  BOOST_TEST(big.mint_reward(5) == UINT64_MAX);
}

BOOST_AUTO_TEST_CASE(RotationKeyReflectsAcceptedSolutions) {
  Sha256PowVerifier v;
  Ledger a(0, cfg(5, /*capacity=*/1));
  Ledger b(0, cfg(5, /*capacity=*/1));
  BOOST_REQUIRE((a.mint_key() == b.mint_key()));
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  apply_block(a, 1, Ledger::make_mint(v, a.mint_key(), A.pub, 5));
  apply_block(b, 1, Ledger::make_mint(v, b.mint_key(), B.pub, 5));
  BOOST_TEST(a.mint_fill() == 0u);
  BOOST_TEST(b.mint_fill() == 0u);
  BOOST_TEST(!(a.mint_key() == b.mint_key()));
}

BOOST_AUTO_TEST_CASE(SnapshotRoundTripPreservesAccumulator) {
  Ledger l(0, cfg(5, /*capacity=*/2));
  Sha256PowVerifier v;
  KeyPair A = KeyPair::generate();
  apply_block(l, 1, Ledger::make_mint(v, l.mint_key(), A.pub, 5));
  BOOST_TEST(l.mint_fill() == 1u);

  Ledger restored(0, cfg(5, 2));
  restored.restore(wire::View(l.snapshot()));
  BOOST_REQUIRE(restored.mint_fill() == 1u);
  BOOST_REQUIRE((restored.mint_key() == l.mint_key()));

  KeyPair B = KeyPair::generate();
  MintOp s2 = Ledger::make_mint(v, l.mint_key(), B.pub, 5);
  apply_block(l, 2, s2);
  apply_block(restored, 2, s2);
  BOOST_TEST(l.mint_fill() == 0u);
  BOOST_TEST((l.mint_key() == restored.mint_key()));
}

BOOST_AUTO_TEST_SUITE_END()
