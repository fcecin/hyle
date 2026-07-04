#include <boost/test/unit_test.hpp>

#include <hyle/core/version.h>
#include <hyle/core/wire.h>

#include <boost/unordered/unordered_flat_map.hpp>
#include <cryptopp/sha.h>
#include <malachite/engine.hpp>

#include <cstdint>
#include <string>
#include <vector>

BOOST_AUTO_TEST_SUITE(SmokeTests)

BOOST_AUTO_TEST_CASE(VersionPresent) {
  BOOST_TEST(std::string(hyle::version()).rfind("hyle", 0) == 0);
}

BOOST_AUTO_TEST_CASE(WireRoundTrip) {
  using namespace hyle::wire;
  Bytes out;
  Writer w(out);
  w.u64(0xdeadbeefcafef00dull);
  w.u32(42);
  const std::vector<uint8_t> payload{1, 2, 3, 4, 5};
  w.bytes(payload);

  Reader r(out);
  BOOST_TEST(r.u64() == 0xdeadbeefcafef00dull);
  BOOST_TEST(r.u32() == 42u);
  View got = r.bytes();
  BOOST_TEST(got.size() == payload.size());
  BOOST_TEST(std::equal(got.begin(), got.end(), payload.begin()));
  BOOST_TEST(r.empty());
}

BOOST_AUTO_TEST_CASE(WireBigEndianCanonical) {
  hyle::wire::Bytes out;
  hyle::wire::Writer(out).u32(1);
  const hyle::wire::Bytes want{0x00, 0x00, 0x00, 0x01};
  BOOST_TEST(out == want);
}

BOOST_AUTO_TEST_CASE(WireShortReadThrows) {
  hyle::wire::Bytes out{0x00, 0x01};
  hyle::wire::Reader r(out);
  BOOST_CHECK_THROW(r.u32(), hyle::wire::Error);
}

BOOST_AUTO_TEST_CASE(StateContainer) {
  boost::unordered_flat_map<std::string, std::string> kv;
  kv["matter"] = "form";
  BOOST_TEST(kv.size() == 1u);
  BOOST_TEST(kv.at("matter") == "form");
}

BOOST_AUTO_TEST_CASE(CryptoppSha256) {
  CryptoPP::SHA256 h;
  unsigned char digest[CryptoPP::SHA256::DIGESTSIZE];
  const unsigned char msg[] = "hyle";
  h.CalculateDigest(digest, msg, sizeof(msg) - 1);
  BOOST_TEST(CryptoPP::SHA256::DIGESTSIZE == 32);
}

BOOST_AUTO_TEST_CASE(MalachiteHeader) {
  malachite::Height h = 1;
  malachite::Round r = malachite::Round::nil();
  BOOST_TEST(h == 1u);
  BOOST_TEST(r.is_nil());
}

BOOST_AUTO_TEST_SUITE_END()
