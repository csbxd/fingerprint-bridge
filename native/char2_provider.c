/* Narrow, private OpenSSL provider for the TLS 1.2 sect283r1 key share.
 * All libcrypto symbols are renamed at build time. No OpenSSL object crosses
 * this interface or is passed to the bridge's independent BoringSSL backend.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "char2_prefix.h"
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#ifdef OPENSSL_NO_EC2M
#error "The char2 provider requires real binary-field EC support"
#endif

typedef struct {
  EC_KEY *key;
} bridge_char2_key;

void bridge_char2_free(void *opaque) {
  bridge_char2_key *context = opaque;
  if (context == NULL) {
    return;
  }
  EC_KEY_free(context->key);
  OPENSSL_clear_free(context, sizeof(*context));
}

void *bridge_char2_generate(uint8_t out[73]) {
  bridge_char2_key *context = NULL;
  const EC_GROUP *group;
  const EC_POINT *public_key;
  if (out == NULL) {
    return NULL;
  }
  memset(out, 0, 73);
  /* The private provider has a separate OpenSSL global namespace. Do not
   * discover configuration files or runtime providers from the host system.
   */
  if (!OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, NULL)) {
    return NULL;
  }
  context = OPENSSL_zalloc(sizeof(*context));
  if (context == NULL) {
    return NULL;
  }
  context->key = EC_KEY_new_by_curve_name(NID_sect283r1);
  if (context->key == NULL || !EC_KEY_generate_key(context->key) ||
      !EC_KEY_check_key(context->key)) {
    goto error;
  }
  group = EC_KEY_get0_group(context->key);
  public_key = EC_KEY_get0_public_key(context->key);
  if (group == NULL || EC_GROUP_get_degree(group) != 283 ||
      public_key == NULL ||
      EC_POINT_point2oct(group, public_key, POINT_CONVERSION_UNCOMPRESSED,
                        out, 73, NULL) != 73) {
    goto error;
  }
  return context;

error:
  bridge_char2_free(context);
  OPENSSL_cleanse(out, 73);
  return NULL;
}

int bridge_char2_derive(void *opaque, uint8_t out[36],
                       const uint8_t *encoded, size_t encoded_len) {
  bridge_char2_key *context = opaque;
  const EC_GROUP *group;
  EC_POINT *peer = NULL;
  EC_POINT *multiple = NULL;
  BN_CTX *scratch = NULL;
  BIGNUM *order = NULL;
  uint8_t canonical[73] = {0};
  uint8_t secret[36] = {0};
  point_conversion_form_t form;
  int ok = 0;
  if (out == NULL) {
    return 0;
  }
  OPENSSL_cleanse(out, 36);
  if (context == NULL || context->key == NULL || encoded == NULL ||
      !((encoded_len == 37 && (encoded[0] == 2 || encoded[0] == 3)) ||
        (encoded_len == 73 && encoded[0] == 4))) {
    return 0;
  }
  /* Coordinates are 283-bit field elements in a fixed 36-byte encoding.
   * Reject reduction of non-canonical coordinates and the hybrid/infinity
   * encodings, rather than silently accepting another wire representation.
   */
  if ((encoded[1] & 0xf8) != 0 ||
      (encoded_len == 73 && (encoded[37] & 0xf8) != 0)) {
    return 0;
  }
  group = EC_KEY_get0_group(context->key);
  if (group == NULL || EC_GROUP_get_curve_name(group) != NID_sect283r1) {
    return 0;
  }
  scratch = BN_CTX_secure_new();
  order = BN_new();
  peer = EC_POINT_new(group);
  multiple = EC_POINT_new(group);
  if (scratch == NULL || order == NULL || peer == NULL || multiple == NULL ||
      !EC_POINT_oct2point(group, peer, encoded, encoded_len, scratch) ||
      EC_POINT_is_at_infinity(group, peer) != 0 ||
      EC_POINT_is_on_curve(group, peer, scratch) != 1) {
    goto done;
  }
  form = encoded_len == 37 ? POINT_CONVERSION_COMPRESSED
                           : POINT_CONVERSION_UNCOMPRESSED;
  if (EC_POINT_point2oct(group, peer, form, canonical, sizeof(canonical),
                        scratch) != encoded_len ||
      CRYPTO_memcmp(canonical, encoded, encoded_len) != 0) {
    goto done;
  }
  /* sect283r1 has cofactor two. Checking only the curve equation would accept
   * small-order points or points outside the prime-order subgroup. This
   * multiplication uses public data only; the private ECDH operation below
   * remains in OpenSSL's reviewed implementation.
   */
  if (!EC_GROUP_get_order(group, order, scratch) ||
      !EC_POINT_mul(group, multiple, NULL, peer, order, scratch) ||
      EC_POINT_is_at_infinity(group, multiple) != 1 ||
      ECDH_compute_key(secret, sizeof(secret), peer, context->key, NULL) != 36) {
    goto done;
  }
  {
    uint8_t nonzero = 0;
    for (size_t i = 0; i < sizeof(secret); i++) {
      nonzero |= secret[i];
    }
    if (nonzero == 0) {
      goto done;
    }
  }
  memcpy(out, secret, sizeof(secret));
  ok = 1;

done:
  OPENSSL_cleanse(secret, sizeof(secret));
  BN_free(order);
  EC_POINT_free(multiple);
  EC_POINT_free(peer);
  BN_CTX_free(scratch);
  return ok;
}
