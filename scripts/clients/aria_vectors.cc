// Synthetic ARIA-GCM interop and authentication fixture.
#include <openssl/aead.h>
#include <openssl/err.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <vector>

static void Require(bool condition, const char *message) {
  if (!condition) {
    std::cerr << message << '\n';
    ERR_print_errors_fp(stderr);
    std::exit(1);
  }
}

static uint8_t Hex(char high, char low) {
  auto nibble = [](char c) -> uint8_t {
    return c <= '9' ? static_cast<uint8_t>(c - '0')
                    : static_cast<uint8_t>(c - 'a' + 10);
  };
  return static_cast<uint8_t>((nibble(high) << 4) | nibble(low));
}

static std::vector<uint8_t> Decode(const char *hex) {
  std::vector<uint8_t> result;
  for (size_t i = 0; hex[i] != 0; i += 2) {
    Require(hex[i + 1] != 0, "odd hex vector");
    result.push_back(Hex(hex[i], hex[i + 1]));
  }
  return result;
}

static void Vector(const EVP_AEAD *aead, size_t key_len,
                   const char *expected_hex) {
  std::vector<uint8_t> key(key_len);
  for (size_t i = 0; i < key.size(); i++) key[i] = static_cast<uint8_t>(i);
  std::array<uint8_t, 12> nonce;
  std::array<uint8_t, 20> ad;
  std::array<uint8_t, 37> plaintext;
  for (size_t i = 0; i < nonce.size(); i++) nonce[i] = 0xa0 + i;
  for (size_t i = 0; i < ad.size(); i++) ad[i] = static_cast<uint8_t>(i);
  for (size_t i = 0; i < plaintext.size(); i++) plaintext[i] = 0x30 + i;

  EVP_AEAD_CTX seal;
  EVP_AEAD_CTX_zero(&seal);
  Require(EVP_AEAD_CTX_init(&seal, aead, key.data(), key.size(),
                            EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr),
          "ARIA-GCM seal init failed");
  std::array<uint8_t, 53> sealed;
  size_t sealed_len = 0;
  Require(EVP_AEAD_CTX_seal(&seal, sealed.data(), &sealed_len, sealed.size(),
                            nonce.data(), nonce.size(), plaintext.data(),
                            plaintext.size(), ad.data(), ad.size()),
          "ARIA-GCM seal failed");
  const auto expected = Decode(expected_hex);
  Require(sealed_len == expected.size() &&
              std::equal(expected.begin(), expected.end(), sealed.begin()),
          "ARIA-GCM differs from independent OpenSSL vector");
  size_t repeated_len = 0;
  Require(!EVP_AEAD_CTX_seal(&seal, sealed.data(), &repeated_len, sealed.size(),
                             nonce.data(), nonce.size(), plaintext.data(),
                             plaintext.size(), ad.data(), ad.size()),
          "ARIA-GCM accepted a repeated TLS explicit nonce");
  ERR_clear_error();
  EVP_AEAD_CTX_cleanup(&seal);

  EVP_AEAD_CTX open;
  EVP_AEAD_CTX_zero(&open);
  Require(EVP_AEAD_CTX_init(&open, aead, key.data(), key.size(),
                            EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr),
          "ARIA-GCM open init failed");
  std::array<uint8_t, 37> opened;
  size_t opened_len = 0;
  Require(EVP_AEAD_CTX_open(&open, opened.data(), &opened_len, opened.size(),
                            nonce.data(), nonce.size(), expected.data(),
                            expected.size(), ad.data(), ad.size()),
          "ARIA-GCM open failed");
  Require(opened_len == plaintext.size() &&
              std::equal(opened.begin(), opened.end(), plaintext.begin()),
          "ARIA-GCM plaintext mismatch");
  auto corrupted = expected;
  corrupted.back() ^= 1;
  opened.fill(0xa5);
  opened_len = 123;
  Require(!EVP_AEAD_CTX_open(&open, opened.data(), &opened_len, opened.size(),
                             nonce.data(), nonce.size(), corrupted.data(),
                             corrupted.size(), ad.data(), ad.size()),
          "ARIA-GCM accepted a corrupted tag");
  Require(opened_len == 0 &&
              std::all_of(opened.begin(), opened.end(),
                          [](uint8_t byte) { return byte == 0; }),
          "failed ARIA-GCM authentication exposed plaintext");
  ERR_clear_error();
  EVP_AEAD_CTX_cleanup(&open);
}

int main() {
  Vector(EVP_aead_aria_128_gcm_tls12(), 16,
         "a94661c7c7ae420fd324039e9bb40e0c1c7209bb54dea538e3edee4322601bfc"
         "583a9c5fbc3270b81e4dc4fb87e4ff793184aad991");
  Vector(EVP_aead_aria_256_gcm_tls12(), 32,
         "63783ed5f6d9bf86ff6548592efe7179f00a67152f907fc1066a73755849fd233"
         "1576b700f6b1aa2cf946a1b6e14c0faf873b9e7f6");
  std::cout << "{\"vectors\":2,\"tampered_tags_rejected\":2,"
               "\"repeated_nonces_rejected\":2}\n";
  return 0;
}
