#include <hyle/core/crypto.h>

#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/xed25519.h>

#include <cstring>
#include <exception>

namespace hyle {

namespace {
CryptoPP::AutoSeededRandomPool& prng() {
  static thread_local CryptoPP::AutoSeededRandomPool rng;
  return rng;
}

PubKey public_from_secret(const PrivKey& secret) {
  CryptoPP::ed25519::Signer signer(reinterpret_cast<const CryptoPP::byte*>(secret.data()));
  CryptoPP::ed25519::Verifier verifier(signer);
  const auto& pub =
      dynamic_cast<const CryptoPP::ed25519PublicKey&>(verifier.GetPublicKey());
  PubKey out{};
  std::memcpy(out.data(), pub.GetPublicKeyBytePtr(), out.size());
  return out;
}
} // namespace

KeyPair KeyPair::generate() {
  CryptoPP::ed25519::Signer signer(prng());
  const auto& sk =
      dynamic_cast<const CryptoPP::ed25519PrivateKey&>(signer.GetPrivateKey());
  KeyPair kp;
  std::memcpy(kp.priv.data(), sk.GetPrivateKeyBytePtr(), kp.priv.size());
  kp.pub = public_from_secret(kp.priv);
  return kp;
}

KeyPair KeyPair::from_secret(const PrivKey& secret) {
  KeyPair kp;
  kp.priv = secret;
  kp.pub = public_from_secret(secret);
  return kp;
}

Sig KeyPair::sign(wire::View msg) const {
  CryptoPP::ed25519::Signer signer(reinterpret_cast<const CryptoPP::byte*>(priv.data()));
  Sig sig{};
  signer.SignMessage(prng(), reinterpret_cast<const CryptoPP::byte*>(msg.data()), msg.size(),
                     reinterpret_cast<CryptoPP::byte*>(sig.data()));
  return sig;
}

bool verify(const PubKey& pub, wire::View msg, const Sig& sig) {
  // a malformed key/point can make CryptoPP throw; must be a rejection, not a crash
  try {
    CryptoPP::ed25519::Verifier verifier(reinterpret_cast<const CryptoPP::byte*>(pub.data()));
    return verifier.VerifyMessage(reinterpret_cast<const CryptoPP::byte*>(msg.data()), msg.size(),
                                  reinterpret_cast<const CryptoPP::byte*>(sig.data()), sig.size());
  } catch (const std::exception&) {
    return false;
  }
}

Hash sha256(wire::View data) {
  Hash out{};
  CryptoPP::SHA256().CalculateDigest(out.data(), data.data(), data.size());
  return out;
}

} // namespace hyle
