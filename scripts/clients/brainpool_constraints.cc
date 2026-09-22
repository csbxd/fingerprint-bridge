// Internal authentication constraints, linked only into the test fixture.
// All ephemeral test keys remain in memory; this fixture opens no sockets.
#include <openssl/ec_key.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <array>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include "ssl/internal.h"

using namespace bssl;

static void Require(bool condition, const char *message) {
  if (!condition) {
    std::cerr << message << '\n';
    ERR_print_errors_fp(stderr);
    std::exit(1);
  }
}

static UniquePtr<EVP_PKEY> Key(int nid) {
  UniquePtr<EC_KEY> ec(EC_KEY_new_by_curve_name(nid));
  UniquePtr<EVP_PKEY> key(EVP_PKEY_new());
  Require(ec && key && EC_KEY_generate_key(ec.get()) &&
              EVP_PKEY_set1_EC_KEY(key.get(), ec.get()), "EC test key generation");
  return key;
}

static std::vector<uint8_t> Sign(EVP_PKEY *key, const EVP_MD *digest,
                               const std::vector<uint8_t> &message) {
  ScopedEVP_MD_CTX ctx;
  size_t size = EVP_PKEY_size(key);
  std::vector<uint8_t> signature(size);
  Require(EVP_DigestSignInit(ctx.get(), nullptr, digest, nullptr, key) &&
              EVP_DigestSign(ctx.get(), signature.data(), &size,
                             message.data(), message.size()), "ECDSA signing");
  signature.resize(size);
  return signature;
}

int main() {
  UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  UniquePtr<SSL> ssl(SSL_new(ctx.get()));
  Require(ctx && ssl, "TLS context allocation");
  SSL_set_connect_state(ssl.get());
  struct Case {
    int curve;
    int nist_curve;
    uint16_t scheme;
    uint16_t nist_scheme;
    const EVP_MD *(*digest)();
    const char *name;
  };
  const std::array<Case, 3> cases = {{
      {NID_brainpoolP256r1, NID_X9_62_prime256v1, 0x081a, 0x0403, EVP_sha256,
       "ecdsa_brainpoolP256r1tls13_sha256"},
      {NID_brainpoolP384r1, NID_secp384r1, 0x081b, 0x0503, EVP_sha384,
       "ecdsa_brainpoolP384r1tls13_sha384"},
      {NID_brainpoolP512r1, NID_secp521r1, 0x081c, 0x0603, EVP_sha512,
       "ecdsa_brainpoolP512r1tls13_sha512"},
  }};
  std::vector<uint8_t> message(64, 0x20);
  const std::string context = "TLS 1.3, server CertificateVerify";
  message.insert(message.end(), context.begin(), context.end());
  message.push_back(0);
  message.insert(message.end(), 32, 0x42);  // synthetic transcript digest
  std::cout << '[';
  bool first = true;
  for (const auto &test : cases) {
    auto key = Key(test.curve);
    auto nist = Key(test.nist_curve);
    auto signature = Sign(key.get(), test.digest(), message);
    ssl->s3->version = TLS1_3_VERSION;
    Require(ssl_pkey_supports_algorithm(ssl.get(), key.get(), test.scheme, true),
            "matching Brainpool curve rejected");
    Require(ssl_public_key_verify(ssl.get(), signature, test.scheme, key.get(), message),
            "valid Brainpool CertificateVerify rejected");
    Require(std::string(SSL_get_signature_algorithm_name(test.scheme, 0)) == test.name,
            "standard Brainpool name changed or truncated");
    Require(EVP_MD_type(SSL_get_signature_algorithm_digest(test.scheme)) ==
                EVP_MD_type(test.digest()), "wrong Brainpool digest mapping");
    for (const auto &other : cases) {
      if (other.scheme != test.scheme) {
        Require(!ssl_pkey_supports_algorithm(ssl.get(), key.get(), other.scheme, true),
                "mismatched Brainpool scheme accepted");
        Require(!ssl_public_key_verify(ssl.get(), signature, other.scheme, key.get(), message),
                "cross-curve CertificateVerify accepted");
      }
    }
    Require(!ssl_pkey_supports_algorithm(ssl.get(), nist.get(), test.scheme, true),
            "NIST curve accepted as Brainpool");
    Require(!ssl_pkey_supports_algorithm(ssl.get(), key.get(), test.nist_scheme, true),
            "Brainpool accepted as NIST curve");
    auto wrong_digest = Sign(key.get(), test.digest == EVP_sha256 ? EVP_sha384() : EVP_sha256(),
                             message);
    Require(!ssl_public_key_verify(ssl.get(), wrong_digest, test.scheme, key.get(), message),
            "wrong signature digest accepted");
    auto corrupted = signature;
    corrupted.back() ^= 1;
    Require(!ssl_public_key_verify(ssl.get(), corrupted, test.scheme, key.get(), message),
            "corrupted signature accepted");
    auto changed_message = message;
    changed_message.back() ^= 1;
    Require(!ssl_public_key_verify(ssl.get(), signature, test.scheme, key.get(), changed_message),
            "changed CertificateVerify transcript accepted");
    for (uint16_t version : {TLS1_1_VERSION, TLS1_2_VERSION}) {
      ssl->s3->version = version;
      Require(!ssl_pkey_supports_algorithm(ssl.get(), key.get(), test.scheme, true),
              "TLS 1.3-only Brainpool scheme accepted by earlier TLS");
      Require(!ssl_public_key_verify(ssl.get(), signature, test.scheme, key.get(), message),
              "TLS 1.3-only signature verified under earlier TLS");
    }
    ERR_clear_error();
    if (!first) std::cout << ',';
    first = false;
    std::cout << "{\"scheme\":" << test.scheme
              << ",\"valid_certificate_verify\":true,\"wrong_curve_rejected\":true"
                 ",\"nist_alias_rejected\":true,\"wrong_digest_rejected\":true"
                 ",\"corrupt_signature_rejected\":true,\"changed_transcript_rejected\":true"
                 ",\"tls11_tls12_rejected\":true}";
  }
  std::cout << "]\n";
}
