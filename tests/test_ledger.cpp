#include <boost/test/unit_test.hpp>

#include "local_cluster.h"

#include <hyle/core/crypto.h>
#include <hyle/services/kv/ledger.h>

#include <vector>

using namespace hyle;

BOOST_AUTO_TEST_SUITE(LedgerTests)

BOOST_AUTO_TEST_CASE(MintThenTransfer) {
  Ledger l;
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();

  l.apply_payload(ApplyContext{1, A.pub}, l.build_payload(1));
  BOOST_TEST(l.balance(A.pub) == Ledger::REWARD);
  BOOST_TEST(l.total() == Ledger::REWARD);

  l.submit(Ledger::make_transfer(A, B.pub, 30));
  l.apply_payload(ApplyContext{2, B.pub}, l.build_payload(2));
  BOOST_TEST(l.balance(B.pub) == Ledger::REWARD + 30);
  BOOST_TEST(l.balance(A.pub) == Ledger::REWARD - 30);
  BOOST_TEST(l.total() == 2 * Ledger::REWARD);
}

BOOST_AUTO_TEST_CASE(InsufficientTransferIsNoOp) {
  Ledger l;
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  l.apply_payload(ApplyContext{1, A.pub}, l.build_payload(1));
  l.submit(Ledger::make_transfer(A, B.pub, Ledger::REWARD + 999));
  l.apply_payload(ApplyContext{2, A.pub}, l.build_payload(2));
  BOOST_TEST(l.balance(A.pub) == 2 * Ledger::REWARD);
  BOOST_TEST(l.balance(B.pub) == 0u);
}

BOOST_AUTO_TEST_CASE(ValidateRejectsBadSignature) {
  Ledger l;
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  l.submit(Ledger::make_transfer(A, B.pub, 10));
  wire::Bytes good = l.build_payload(1);
  BOOST_TEST(l.validate_payload(good));
  wire::Bytes bad = good;
  bad.back() ^= 0xff;
  BOOST_TEST(!l.validate_payload(bad));
}

BOOST_AUTO_TEST_CASE(SnapshotRoundTrip) {
  Ledger l;
  KeyPair A = KeyPair::generate();
  l.apply_payload(ApplyContext{1, A.pub}, l.build_payload(1));
  wire::Bytes snap = l.snapshot();
  Ledger l2;
  l2.restore(snap);
  BOOST_TEST(l2.balance(A.pub) == Ledger::REWARD);
  BOOST_TEST(l2.total() == Ledger::REWARD);
}

BOOST_AUTO_TEST_CASE(MultiNodeMintConverges) {
  std::vector<Ledger> led(4);
  std::vector<StateMachine*> sms;
  for (auto& x : led) sms.push_back(&x);
  LocalCluster c(sms);
  c.run(8, 4);

  Hash h0 = c.nodes[0]->composite_hash();
  for (int i = 1; i < 4; i++) BOOST_TEST((c.nodes[i]->composite_hash() == h0));

  for (int i = 0; i < 4; i++) BOOST_TEST(led[i].total() == 8 * Ledger::REWARD);
  BOOST_TEST(led[0].accounts() >= 2u);
}

BOOST_AUTO_TEST_CASE(RentDecaysAndCellIsEvicted) {
  Ledger l(1);
  KeyPair A = KeyPair::generate();
  KeyPair K = KeyPair::generate();
  KeyPair C = KeyPair::generate();

  l.apply_payload(ApplyContext{1, A.pub}, l.build_payload(1));
  l.submit(Ledger::make_transfer(A, K.pub, 5));
  l.apply_payload(ApplyContext{2, A.pub}, l.build_payload(2));
  BOOST_TEST(l.balance(K.pub) == 5u);

  for (uint64_t h = 3; h <= 19; ++h) l.apply_payload(ApplyContext{h, A.pub}, l.build_payload(h));
  BOOST_TEST(l.exists(K.pub));

  l.submit_evict(K.pub, C.pub);
  l.apply_payload(ApplyContext{20, A.pub}, l.build_payload(20));
  BOOST_TEST(!l.exists(K.pub));
  BOOST_TEST(l.balance(C.pub) == Ledger::BOUNTY);
}

BOOST_AUTO_TEST_CASE(EvictFailsOnSolventCell) {
  Ledger l(1);
  KeyPair A = KeyPair::generate();
  KeyPair K = KeyPair::generate();
  KeyPair C = KeyPair::generate();

  l.apply_payload(ApplyContext{1, A.pub}, l.build_payload(1));
  l.submit(Ledger::make_transfer(A, K.pub, 100));
  l.apply_payload(ApplyContext{2, A.pub}, l.build_payload(2));

  l.submit_evict(K.pub, C.pub);
  l.apply_payload(ApplyContext{3, A.pub}, l.build_payload(3));
  BOOST_TEST(l.exists(K.pub));
  BOOST_TEST(l.balance(K.pub) == 99u);
  BOOST_TEST(l.balance(C.pub) == 0u);
}

BOOST_AUTO_TEST_CASE(MultiNodeRentConverges) {
  std::vector<Ledger> led;
  led.reserve(4);
  for (int i = 0; i < 4; i++) led.emplace_back(1);
  std::vector<StateMachine*> sms;
  for (auto& x : led) sms.push_back(&x);
  LocalCluster c(sms);
  c.run(8, 4);

  Hash h0 = c.nodes[0]->composite_hash();
  for (int i = 1; i < 4; i++) BOOST_TEST((c.nodes[i]->composite_hash() == h0));
  uint64_t t0 = led[0].total();
  for (int i = 1; i < 4; i++) BOOST_TEST(led[i].total() == t0);
}

BOOST_AUTO_TEST_CASE(SignatureCoversAmountAndRecipient) {
  Ledger l;
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  KeyPair C = KeyPair::generate();

  auto payload_with = [](const XferOp& o) {
    wire::Bytes raw;
    wire::Writer w(raw);
    w.count(1);
    w.raw(wire::View(o.from.data(), o.from.size()));
    w.raw(wire::View(o.to.data(), o.to.size()));
    w.u64(o.amount);
    w.u64(o.seq);
    w.raw(wire::View(o.sig.data(), o.sig.size()));
    w.count(0);
    w.count(0);
    w.count(0);
    return raw;
  };

  XferOp amt = Ledger::make_transfer(A, B.pub, 10);
  amt.amount = 11;
  wire::Bytes p1 = payload_with(amt);
  BOOST_TEST(!l.validate_payload(wire::View(p1.data(), p1.size())));

  XferOp dest = Ledger::make_transfer(A, B.pub, 10);
  dest.to = C.pub;
  wire::Bytes p2 = payload_with(dest);
  BOOST_TEST(!l.validate_payload(wire::View(p2.data(), p2.size())));

  l.submit(amt);
  wire::Bytes built = l.build_payload(1);
  BOOST_TEST(l.validate_payload(wire::View(built.data(), built.size())));
}

BOOST_AUTO_TEST_CASE(TransferReplayRejected) {
  Ledger l;
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  l.apply_payload(ApplyContext{1, A.pub}, l.build_payload(1));
  BOOST_TEST(l.account_seq(A.pub) == 0u);

  const XferOp t0 = Ledger::make_transfer(A, B.pub, 30, /*seq=*/0);
  l.submit(t0);
  l.apply_payload(ApplyContext{2, PubKey{}}, l.build_payload(2));
  BOOST_TEST(l.balance(B.pub) == 30u);
  BOOST_TEST(l.account_seq(A.pub) == 1u);

  l.submit(t0);
  l.apply_payload(ApplyContext{3, PubKey{}}, l.build_payload(3));
  BOOST_TEST(l.balance(B.pub) == 30u);
  BOOST_TEST(l.balance(A.pub) == Ledger::REWARD - 30u);
  BOOST_TEST(l.account_seq(A.pub) == 1u);

  l.submit(Ledger::make_transfer(A, B.pub, 10, /*seq=*/5));
  l.apply_payload(ApplyContext{4, PubKey{}}, l.build_payload(4));
  BOOST_TEST(l.balance(B.pub) == 30u);

  l.submit(Ledger::make_transfer(A, B.pub, 10, /*seq=*/1));
  l.apply_payload(ApplyContext{5, PubKey{}}, l.build_payload(5));
  BOOST_TEST(l.balance(B.pub) == 40u);
  BOOST_TEST(l.account_seq(A.pub) == 2u);
  BOOST_TEST(l.total() == Ledger::REWARD);
}

BOOST_AUTO_TEST_CASE(TransferBoundaryExactAndOverspend) {
  Ledger l;
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  KeyPair D = KeyPair::generate();
  l.apply_payload(ApplyContext{1, A.pub}, l.build_payload(1));

  l.submit(Ledger::make_transfer(A, B.pub, Ledger::REWARD));
  l.apply_payload(ApplyContext{2, PubKey{}}, l.build_payload(2));
  BOOST_TEST(l.balance(B.pub) == Ledger::REWARD);
  BOOST_TEST(l.exists(A.pub));
  BOOST_TEST(l.balance(A.pub) == 0u);
  BOOST_TEST(l.account_seq(A.pub) == 1u);
  BOOST_TEST(l.total() == Ledger::REWARD);

  l.submit(Ledger::make_transfer(B, D.pub, Ledger::REWARD + 1));
  l.apply_payload(ApplyContext{3, PubKey{}}, l.build_payload(3));
  BOOST_TEST(l.balance(B.pub) == Ledger::REWARD);
  BOOST_TEST(!l.exists(D.pub));
}

BOOST_AUTO_TEST_CASE(SelfTransferIsNoOp) {
  Ledger l;
  KeyPair A = KeyPair::generate();
  l.apply_payload(ApplyContext{1, A.pub}, l.build_payload(1));
  l.submit(Ledger::make_transfer(A, A.pub, 30));
  l.apply_payload(ApplyContext{2, PubKey{}}, l.build_payload(2));
  BOOST_TEST(l.balance(A.pub) == Ledger::REWARD);
  BOOST_TEST(l.total() == Ledger::REWARD);
}

BOOST_AUTO_TEST_CASE(ConservationAcrossRentBurnAndBounty) {
  Ledger l(1);
  KeyPair A = KeyPair::generate();
  KeyPair K = KeyPair::generate();
  KeyPair C = KeyPair::generate();

  l.apply_payload(ApplyContext{1, A.pub}, l.build_payload(1));
  BOOST_TEST(l.total() == Ledger::REWARD);

  l.submit(Ledger::make_transfer(A, K.pub, 50));
  l.apply_payload(ApplyContext{2, PubKey{}}, l.build_payload(2));
  BOOST_TEST(l.total() == 99u);

  l.submit_evict(K.pub, C.pub);
  l.apply_payload(ApplyContext{52, PubKey{}}, l.build_payload(52));
  BOOST_TEST(!l.exists(K.pub));
  BOOST_TEST(l.balance(C.pub) == Ledger::BOUNTY);
  BOOST_TEST(l.total() == 59u);
}

BOOST_AUTO_TEST_CASE(ProposerDropsInvalidOpsFromOwnBlock) {
  Ledger l;
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  KeyPair C = KeyPair::generate();
  l.apply_payload(ApplyContext{1, A.pub}, l.build_payload(1));
  XferOp good = Ledger::make_transfer(A, B.pub, 10, /*seq=*/0);
  XferOp bad = Ledger::make_transfer(A, C.pub, 20, /*seq=*/0);
  bad.sig[0] ^= 0xff;
  l.submit(good);
  l.submit(bad);
  wire::Bytes payload = l.build_payload(2);
  BOOST_TEST(l.validate_payload(wire::View(payload)));
  l.apply_payload(ApplyContext{2, PubKey{}}, wire::View(payload));
  BOOST_TEST(l.balance(B.pub) == 10u);
  BOOST_TEST(l.balance(C.pub) == 0u);
}

BOOST_AUTO_TEST_CASE(ApplySkipsBadSignatureOpAppliesGoodOnes) {
  Ledger l;
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  KeyPair C = KeyPair::generate();
  l.apply_payload(ApplyContext{1, A.pub}, l.build_payload(1));
  XferOp good = Ledger::make_transfer(A, B.pub, 10);
  XferOp bad = Ledger::make_transfer(A, C.pub, 20);
  bad.sig[0] ^= 0xff;
  l.submit(good);
  l.submit(bad);
  wire::Bytes payload = l.build_payload(2);
  l.apply_payload(ApplyContext{2, PubKey{}}, wire::View(payload));
  BOOST_TEST(l.balance(B.pub) == 10u);
  BOOST_TEST(l.balance(C.pub) == 0u);
  BOOST_TEST(l.balance(A.pub) == Ledger::REWARD - 10u);
  BOOST_TEST(l.total() == Ledger::REWARD);
}

BOOST_AUTO_TEST_CASE(ZeroAmountTransferAndEvictMintNothing) {
  Ledger l(1);
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  KeyPair C = KeyPair::generate();
  l.apply_payload(ApplyContext{1, A.pub}, l.build_payload(1));
  const uint64_t before = l.total();
  l.submit(Ledger::make_transfer(A, B.pub, 0));
  l.submit_evict(B.pub, C.pub);
  l.apply_payload(ApplyContext{2, PubKey{}}, l.build_payload(2));
  BOOST_TEST(!l.exists(B.pub));
  BOOST_TEST(l.balance(C.pub) == 0u);
  BOOST_TEST(l.total() == before);
}

BOOST_AUTO_TEST_CASE(RestoreRejectsMalformedAndKeepsStateIntact) {
  Ledger l;
  KeyPair A = KeyPair::generate();
  KeyPair B = KeyPair::generate();
  l.apply_payload(ApplyContext{1, A.pub}, l.build_payload(1));
  l.submit(Ledger::make_transfer(A, B.pub, 30));
  l.apply_payload(ApplyContext{2, PubKey{}}, l.build_payload(2));
  const uint64_t total_before = l.total();
  const uint64_t a_before = l.balance(A.pub);
  BOOST_TEST(l.balance(B.pub) == 30u);

  const wire::Bytes snap = l.snapshot();

  wire::Bytes truncated(snap.begin(), snap.end() - 1);
  BOOST_CHECK_THROW(l.restore(wire::View(truncated.data(), truncated.size())), wire::Error);
  BOOST_TEST(l.total() == total_before);
  BOOST_TEST(l.balance(A.pub) == a_before);
  BOOST_TEST(l.balance(B.pub) == 30u);

  wire::Bytes trailing = snap;
  trailing.push_back(0xff);
  BOOST_CHECK_THROW(l.restore(wire::View(trailing.data(), trailing.size())), wire::Error);
  BOOST_TEST(l.total() == total_before);

  l.restore(wire::View(snap.data(), snap.size()));
  BOOST_TEST(l.balance(B.pub) == 30u);
}

BOOST_AUTO_TEST_CASE(MalformedPayloadRejectedNotCrash) {
  Ledger l;
  BOOST_TEST(!l.validate_payload(wire::Bytes{0, 0, 0, 1}));
  BOOST_TEST(!l.validate_payload(wire::Bytes{0, 0, 0, 1, 1, 2, 3}));
  BOOST_TEST(!l.validate_payload(wire::Bytes{0xff, 0xff, 0xff, 0xff}));
  BOOST_TEST(!l.validate_payload(wire::Bytes{}));
}

BOOST_AUTO_TEST_SUITE_END()
