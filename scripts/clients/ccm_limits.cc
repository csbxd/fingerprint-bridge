// Internal record-layer regression fixture. All keys are fixed synthetic test
// data. This binary is never linked into the bridge and opens no sockets.
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <iostream>
#include <vector>

#include "ssl/internal.h"

using namespace bssl;

static constexpr uint64_t kLimit = UINT64_C(1) << 23;
static constexpr std::array<uint8_t, 7> kPlaintext = {'c', 'c', 'm', 0, 255, 'x', 'y'};

static void Require(bool condition, const char *message) {
  if (!condition) {
    std::cerr << message << '\n';
    ERR_print_errors_fp(stderr);
    std::exit(1);
  }
}

static UniquePtr<SSL> Connection(SSL_CTX *ctx, uint16_t suite, uint16_t version) {
  UniquePtr<SSL> ssl(SSL_new(ctx));
  Require(ssl != nullptr, "SSL_new failed");
  SSL_set_connect_state(ssl.get());
  ssl->s3->version = version;
  const SSL_CIPHER *cipher = SSL_get_cipher_by_value(suite);
  Require(cipher != nullptr, "unknown CCM test suite");
  const EVP_AEAD *aead;
  size_t mac_len, iv_len;
  Require(ssl_cipher_get_evp_aead(&aead, &mac_len, &iv_len, cipher, version),
          "CCM AEAD not available");
  Require(mac_len == 0, "CCM unexpectedly has separate MAC key");
  std::vector<uint8_t> key(EVP_AEAD_key_length(aead), 0x37);
  std::vector<uint8_t> iv(iv_len, 0x42);
  ssl->s3->aead_write_ctx = SSLAEADContext::Create(
      evp_aead_seal, version, cipher, key, {}, iv);
  ssl->s3->aead_read_ctx = SSLAEADContext::Create(
      evp_aead_open, version, cipher, key, {}, iv);
  Require(ssl->s3->aead_write_ctx && ssl->s3->aead_read_ctx,
          "CCM record context creation failed");
  ssl->s3->established_session.reset(SSL_SESSION_new(ctx));
  Require(ssl->s3->established_session != nullptr, "session allocation failed");
  ssl->s3->established_session->ssl_version = version;
  ssl->s3->established_session->cipher = cipher;
  std::array<uint8_t, 32> secret{};
  secret.fill(0x53);
  ssl->s3->read_traffic_secret.CopyFrom(secret);
  ssl->s3->write_traffic_secret.CopyFrom(secret);
  return ssl;
}

static std::vector<uint8_t> Seal(SSL *ssl) {
  std::vector<uint8_t> wire(256);
  size_t len = 0;
  Require(tls_seal_record(ssl, wire.data(), &len, wire.size(),
                          SSL3_RT_APPLICATION_DATA, kPlaintext.data(),
                          kPlaintext.size()), "last permitted record rejected");
  wire.resize(len);
  return wire;
}

static ssl_open_record_t Open(SSL *ssl, std::vector<uint8_t> wire,
                              uint8_t *alert) {
  uint8_t type = 0;
  size_t consumed = 0;
  Span<uint8_t> plaintext;
  const auto result = tls_open_record(ssl, &type, &plaintext, &consumed,
                                      alert, Span(wire.data(), wire.size()));
  if (result == ssl_open_record_success) {
    Require(type == SSL3_RT_APPLICATION_DATA, "wrong decrypted content type");
    Require(consumed == wire.size(), "partial record consumed");
    Require(plaintext.size() == kPlaintext.size() &&
            std::equal(plaintext.begin(), plaintext.end(), kPlaintext.begin()),
            "wrong decrypted plaintext");
  }
  return result;
}

static void Boundary(SSL_CTX *ctx, uint16_t suite, uint16_t version, bool *first) {
  auto ssl = Connection(ctx, suite, version);
  ssl->s3->write_sequence = kLimit - 1;
  ssl->s3->read_sequence = kLimit - 1;
  auto wire = Seal(ssl.get());
  uint8_t alert = 0;
  Require(Open(ssl.get(), wire, &alert) == ssl_open_record_success,
          "last permitted receive rejected");
  Require(ssl->s3->write_sequence == kLimit && ssl->s3->read_sequence == kLimit,
          "per-key counters did not advance to limit");
  std::array<uint8_t, 256> rejected;
  size_t len = 0;
  ERR_clear_error();
  Require(!tls_seal_record(ssl.get(), rejected.data(), &len, rejected.size(),
                           SSL3_RT_APPLICATION_DATA, kPlaintext.data(),
                           kPlaintext.size()), "record above write budget accepted");
  Require(ERR_GET_REASON(ERR_peek_last_error()) == ERR_R_OVERFLOW,
          "write budget failed for unrelated reason");
  ERR_clear_error();
  Require(Open(ssl.get(), wire, &alert) == ssl_open_record_error,
          "record above read budget accepted");
  Require(alert == SSL_AD_INTERNAL_ERROR &&
          ERR_GET_REASON(ERR_peek_last_error()) == ERR_R_OVERFLOW,
          "read budget failed for unrelated reason");
  ERR_clear_error();
  bool rotated = false;
  if (version == TLS1_3_VERSION) {
    const std::vector<uint8_t> old_secret(
        ssl->s3->write_traffic_secret.data(),
        ssl->s3->write_traffic_secret.data() + ssl->s3->write_traffic_secret.size());
    Require(tls13_rotate_traffic_key(ssl.get(), evp_aead_seal) &&
            tls13_rotate_traffic_key(ssl.get(), evp_aead_open),
            "TLS 1.3 traffic-key rotation failed");
    Require(ssl->s3->write_traffic_secret.size() == old_secret.size() &&
            !std::equal(old_secret.begin(), old_secret.end(),
                        ssl->s3->write_traffic_secret.data()),
            "traffic-key rotation did not change the traffic secret");
    Require(ssl->s3->write_sequence == 0 && ssl->s3->read_sequence == 0,
            "key rotation did not reset per-key counters");
    auto rotated_wire = Seal(ssl.get());
    Require(Open(ssl.get(), rotated_wire, &alert) == ssl_open_record_success,
            "record with rotated traffic keys failed");
    Require(rotated_wire != wire, "key rotation repeated old ciphertext");
    rotated = true;
  }
  if (!*first) std::cout << ',';
  *first = false;
  std::cout << "{\"kind\":\"record-budget\",\"suite\":" << suite
            << ",\"tls_version\":" << version
            << ",\"limit\":" << kLimit
            << ",\"last_record_passed\":true,\"next_record_rejected\":true"
            << ",\"key_update_rotation_passed\":" << (rotated ? "true" : "null") << '}';
}

static void TrialDecryption(SSL_CTX *ctx, uint16_t suite, bool reject,
                            bool *first) {
  auto ssl = Connection(ctx, suite, TLS1_3_VERSION);
  auto wire = Seal(ssl.get());
  wire.back() ^= 1;
  ssl->s3->skip_early_data = true;
  uint8_t alert = 0;
  const auto result = Open(ssl.get(), wire, &alert);
  Require(result == (reject ? ssl_open_record_error : ssl_open_record_discard),
          "unexpected rejected-0RTT authentication behavior");
  if (reject) {
    Require(alert == SSL_AD_BAD_RECORD_MAC,
            "CCM8 trial-decryption failure did not raise bad_record_mac");
    Require(ssl->s3->early_data_skipped == 0,
            "CCM8 authentication failure was counted as skipped early data");
  } else {
    Require(ssl->s3->early_data_skipped == wire.size(),
            "control cipher lost existing bounded early-data discard behavior");
  }
  Require(ssl->s3->read_sequence == 0,
          "failed authentication advanced read sequence");
  ERR_clear_error();
  if (!*first) std::cout << ',';
  *first = false;
  std::cout << "{\"kind\":\"rejected-0rtt-trial\",\"suite\":" << suite
            << ",\"first_failure_fatal\":" << (reject ? "true" : "false") << '}';
}

int main() {
  UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
  Require(ctx != nullptr, "context allocation failed");
  bool first = true;
  std::cout << '[';
  for (uint16_t suite : {0xc09c, 0xc09d, 0xc09e, 0xc09f, 0xc0a0, 0xc0a1,
                         0xc0a2, 0xc0a3, 0xc0ac, 0xc0ad, 0xc0ae, 0xc0af}) {
    Boundary(ctx.get(), suite, TLS1_2_VERSION, &first);
  }
  for (uint16_t suite : {0x1304, 0x1305}) {
    Boundary(ctx.get(), suite, TLS1_3_VERSION, &first);
  }
  TrialDecryption(ctx.get(), 0x1305, true, &first);
  TrialDecryption(ctx.get(), 0x1304, false, &first);
  TrialDecryption(ctx.get(), 0x1301, false, &first);
  std::cout << "]\n";
  return 0;
}
