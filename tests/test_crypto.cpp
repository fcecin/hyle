#include <boost/test/unit_test.hpp>

#include <hyle/core/crypto.h>

#include <string>
#include <vector>

using namespace hyle;

static wire::View sv(const std::string& s) {
  return wire::View(reinterpret_cast<const uint8_t*>(s.data()), s.size());
}

BOOST_AUTO_TEST_SUITE(CryptoTests)

BOOST_AUTO_TEST_CASE(SignVerifyRoundTrip) {
  KeyPair kp = KeyPair::generate();
  const std::string msg = "the matter takes form";
  Sig sig = kp.sign(sv(msg));
  BOOST_TEST(verify(kp.pub, sv(msg), sig));
}

BOOST_AUTO_TEST_CASE(WrongMessageFailsVerify) {
  KeyPair kp = KeyPair::generate();
  Sig sig = kp.sign(sv("height 1"));
  BOOST_TEST(!verify(kp.pub, sv("height 2"), sig));
}

BOOST_AUTO_TEST_CASE(WrongKeyFailsVerify) {
  KeyPair a = KeyPair::generate();
  KeyPair b = KeyPair::generate();
  Sig sig = a.sign(sv("vote"));
  BOOST_TEST(!verify(b.pub, sv("vote"), sig));
}

BOOST_AUTO_TEST_CASE(FromSecretIsDeterministic) {
  PrivKey secret{};
  for (size_t i = 0; i < secret.size(); ++i) secret[i] = static_cast<uint8_t>(i + 1);
  KeyPair a = KeyPair::from_secret(secret);
  KeyPair b = KeyPair::from_secret(secret);
  BOOST_TEST(a.pub == b.pub);
  BOOST_TEST(a.priv == b.priv);
  BOOST_TEST(verify(b.pub, sv("x"), a.sign(sv("x"))));
}

BOOST_AUTO_TEST_CASE(Sha256KnownAnswer) {
  Hash h = sha256(sv("abc"));
  const Hash want{0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
                  0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
                  0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
  BOOST_TEST(h == want);
}

BOOST_AUTO_TEST_CASE(ZeroKeyAndEmptyMessageEdges) {
  KeyPair kp = KeyPair::generate();
  Sig sig = kp.sign(sv("x"));

  PubKey zero{};
  BOOST_TEST(!verify(zero, sv("x"), sig));

  Sig empty_sig = kp.sign(wire::View{});
  BOOST_TEST(verify(kp.pub, wire::View{}, empty_sig));
  BOOST_TEST(!verify(kp.pub, sv("x"), empty_sig));

  Hash h = sha256(wire::View{});
  const Hash want{0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
                  0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
                  0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
  BOOST_TEST(h == want);
}

BOOST_AUTO_TEST_SUITE_END()
