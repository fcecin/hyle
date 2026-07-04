#include <boost/test/unit_test.hpp>

#include <hyle/services/kv/ops.h>
#include <hyle/services/kv/state.h>

#include <string>
#include <vector>

using namespace hyle;

static wire::View sv(const std::string& s) {
  return wire::View(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}
static std::string str(const wire::Bytes* b) {
  return b ? std::string(b->begin(), b->end()) : std::string("<null>");
}

BOOST_AUTO_TEST_SUITE(StateTests)

BOOST_AUTO_TEST_CASE(PutGetDelete) {
  State s;
  s.apply(Op::put(sv("a"), sv("1")));
  s.apply(Op::put(sv("b"), sv("2")));
  BOOST_TEST(s.size() == 2u);
  BOOST_TEST(str(s.get(sv("a"))) == "1");
  BOOST_TEST(str(s.get(sv("b"))) == "2");
  BOOST_TEST(s.get(sv("z")) == static_cast<const wire::Bytes*>(nullptr));

  s.apply(Op::put(sv("a"), sv("9")));
  BOOST_TEST(str(s.get(sv("a"))) == "9");

  s.apply(Op::del(sv("a")));
  BOOST_TEST(s.get(sv("a")) == static_cast<const wire::Bytes*>(nullptr));
  BOOST_TEST(s.size() == 1u);

  s.apply(Op::del(sv("missing")));
  BOOST_TEST(s.size() == 1u);
}

BOOST_AUTO_TEST_CASE(EmptyStateHashDefined) {
  State s;
  wire::Bytes c = s.canonical();
  const wire::Bytes want{0x00, 0x00, 0x00, 0x00};
  BOOST_TEST(c == want);
  Hash h = s.app_hash();
  BOOST_TEST(h.size() == 32u);
}

BOOST_AUTO_TEST_CASE(InsertionOrderDoesNotMatter) {
  State a, b;
  a.apply(Op::put(sv("x"), sv("1")));
  a.apply(Op::put(sv("y"), sv("2")));
  a.apply(Op::put(sv("z"), sv("3")));

  b.apply(Op::put(sv("z"), sv("3")));
  b.apply(Op::put(sv("x"), sv("1")));
  b.apply(Op::put(sv("y"), sv("2")));

  BOOST_TEST(a.canonical() == b.canonical());
  BOOST_TEST(a.app_hash() == b.app_hash());
}

BOOST_AUTO_TEST_CASE(DifferentStateDifferentHash) {
  State a, b;
  a.apply(Op::put(sv("k"), sv("v")));
  b.apply(Op::put(sv("k"), sv("w")));
  BOOST_TEST(!(a.app_hash() == b.app_hash()));
}

BOOST_AUTO_TEST_CASE(DeleteReturnsToEmptyHash) {
  State empty;
  State s;
  s.apply(Op::put(sv("k"), sv("v")));
  s.apply(Op::del(sv("k")));
  BOOST_TEST(s.app_hash() == empty.app_hash());
}

BOOST_AUTO_TEST_CASE(OpBatchRoundTrip) {
  std::vector<Op> batch{
      Op::put(sv("alpha"), sv("one")),
      Op::del(sv("beta")),
      Op::put(sv("gamma"), sv("")),
  };
  wire::Bytes enc = encode_ops(batch);
  std::vector<Op> dec = decode_ops(enc);
  BOOST_TEST((dec == batch));
}

BOOST_AUTO_TEST_CASE(ApplyDecodedBatchMatchesDirect) {
  std::vector<Op> batch{
      Op::put(sv("a"), sv("1")),
      Op::put(sv("b"), sv("2")),
      Op::del(sv("a")),
  };
  State direct;
  direct.apply(batch);

  State viaWire;
  viaWire.apply(decode_ops(encode_ops(batch)));

  BOOST_TEST(direct.app_hash() == viaWire.app_hash());
}

BOOST_AUTO_TEST_CASE(DecodeRejectsTrailingBytes) {
  wire::Bytes enc = encode_ops({Op::put(sv("a"), sv("1"))});
  enc.push_back(0xff);
  BOOST_CHECK_THROW(decode_ops(enc), wire::Error);
}

BOOST_AUTO_TEST_CASE(ReaderRejectsWrappingRawSize) {
  std::vector<uint8_t> buf{1, 2, 3, 4};
  wire::Reader r(wire::View(buf.data(), buf.size()));
  BOOST_CHECK_THROW(r.raw(static_cast<size_t>(-1)), wire::Error);
  BOOST_CHECK_THROW(r.raw(static_cast<size_t>(-1) - 1), wire::Error);
  BOOST_CHECK_NO_THROW(r.raw(4));
}

BOOST_AUTO_TEST_CASE(RestoreIsAtomicAndCanonicalChecked) {
  State s;
  s.apply({Op::put(sv("alpha"), sv("1")), Op::put(sv("beta"), sv("2"))});
  const Hash before = s.app_hash();
  const wire::Bytes good = s.canonical();

  wire::Bytes truncated(good.begin(), good.end() - 1);
  BOOST_CHECK_THROW(s.restore(wire::View(truncated.data(), truncated.size())), wire::Error);
  BOOST_TEST((s.app_hash() == before));

  wire::Bytes trailing = good;
  trailing.push_back(0x00);
  BOOST_CHECK_THROW(s.restore(wire::View(trailing.data(), trailing.size())), wire::Error);
  BOOST_TEST((s.app_hash() == before));

  wire::Bytes bad;
  wire::Writer w(bad);
  w.count(2);
  w.bytes(sv("b"));
  w.bytes(sv("x"));
  w.bytes(sv("a"));
  w.bytes(sv("y"));
  BOOST_CHECK_THROW(s.restore(wire::View(bad.data(), bad.size())), wire::Error);
  BOOST_TEST((s.app_hash() == before));

  State t;
  t.restore(wire::View(good.data(), good.size()));
  BOOST_TEST((t.app_hash() == before));
}

BOOST_AUTO_TEST_SUITE_END()
