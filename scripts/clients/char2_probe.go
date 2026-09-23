// Independent loopback TLS 1.2 peer using the system OpenSSL binary-field
// implementation. The bridge links a separate pinned provider; this peer never
// links or imports it. All keys, certificates and traffic are synthetic.
package main

/*
#cgo LDFLAGS: -lcrypto
#cgo CFLAGS: -Wno-deprecated-declarations
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/crypto.h>
#include <openssl/bn.h>

static EC_KEY *char2_key(void) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_sect283r1);
    if (!key || EC_KEY_generate_key(key) != 1) {
        EC_KEY_free(key);
        return NULL;
    }
    return key;
}
static int char2_public(EC_KEY *key, int compressed, unsigned char *out) {
    return (int)EC_POINT_point2oct(EC_KEY_get0_group(key),
        EC_KEY_get0_public_key(key), compressed ? POINT_CONVERSION_COMPRESSED :
        POINT_CONVERSION_UNCOMPRESSED, out, 73, NULL);
}
static int char2_secret(EC_KEY *key, const unsigned char *encoded, size_t size,
                       unsigned char *secret) {
    const EC_GROUP *group = EC_KEY_get0_group(key);
    EC_POINT *peer = EC_POINT_new(group);
    int n = 0;
    if (peer && EC_POINT_oct2point(group, peer, encoded, size, NULL) == 1 &&
        EC_POINT_is_at_infinity(group, peer) == 0 &&
        EC_POINT_is_on_curve(group, peer, NULL) == 1)
        n = ECDH_compute_key(secret, 36, peer, key, NULL);
    EC_POINT_free(peer);
    return n;
}
// Verify the negative fixture independently: on sect283r1, compressed x=0
// is the unique nontrivial point of order two. Its doubled value is infinity,
// but multiplying it by the odd prime subgroup order is not infinity.
static int char2_order_two(void) {
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sect283r1);
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT *point = group ? EC_POINT_new(group) : NULL;
    EC_POINT *twice = group ? EC_POINT_new(group) : NULL;
    EC_POINT *times_order = group ? EC_POINT_new(group) : NULL;
    BIGNUM *order = BN_new();
    unsigned char encoded[37] = {2};
    int ok = group && ctx && point && twice && times_order && order &&
        EC_POINT_oct2point(group, point, encoded, sizeof(encoded), ctx) == 1 &&
        EC_POINT_is_on_curve(group, point, ctx) == 1 &&
        EC_POINT_is_at_infinity(group, point) == 0 &&
        EC_POINT_dbl(group, twice, point, ctx) == 1 &&
        EC_POINT_is_at_infinity(group, twice) == 1 &&
        EC_GROUP_get_order(group, order, ctx) == 1 &&
        EC_POINT_mul(group, times_order, NULL, point, order, ctx) == 1 &&
        EC_POINT_is_at_infinity(group, times_order) == 0;
    BN_free(order); EC_POINT_free(times_order); EC_POINT_free(twice);
    EC_POINT_free(point); BN_CTX_free(ctx); EC_GROUP_free(group);
    return ok;
}
static int char2_off_curve(void) {
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sect283r1);
    EC_POINT *point = group ? EC_POINT_new(group) : NULL;
    unsigned char encoded[73] = {4};
    int invalid = group && point &&
        EC_POINT_oct2point(group, point, encoded, sizeof(encoded), NULL) == 0;
    EC_POINT_free(point); EC_GROUP_free(group);
    return invalid;
}
// A point outside the prime-order subgroup need not have small order itself.
// Add the order-two point to a fresh prime-order public key and independently
// prove that this on-curve, nontrivial point still has nP != infinity.
static int char2_mixed_subgroup(EC_KEY *key, unsigned char *out) {
    const EC_GROUP *group = EC_KEY_get0_group(key);
    BN_CTX *ctx = BN_CTX_new();
    EC_POINT *order_two = EC_POINT_new(group);
    EC_POINT *mixed = EC_POINT_new(group);
    EC_POINT *check = EC_POINT_new(group);
    BIGNUM *order = BN_new();
    unsigned char encoded[37] = {2};
    int n = 0;
    if (ctx && order_two && mixed && check && order &&
        EC_POINT_oct2point(group, order_two, encoded, sizeof(encoded), ctx) == 1 &&
        EC_POINT_add(group, mixed, EC_KEY_get0_public_key(key), order_two, ctx) == 1 &&
        EC_POINT_is_on_curve(group, mixed, ctx) == 1 &&
        EC_POINT_is_at_infinity(group, mixed) == 0 &&
        EC_POINT_dbl(group, check, mixed, ctx) == 1 &&
        EC_POINT_is_at_infinity(group, check) == 0 &&
        EC_GROUP_get_order(group, order, ctx) == 1 &&
        EC_POINT_mul(group, check, NULL, mixed, order, ctx) == 1 &&
        EC_POINT_is_at_infinity(group, check) == 0)
        n = (int)EC_POINT_point2oct(group, mixed, POINT_CONVERSION_COMPRESSED,
                                   out, 37, ctx);
    BN_free(order); EC_POINT_free(check); EC_POINT_free(mixed);
    EC_POINT_free(order_two); BN_CTX_free(ctx);
    return n;
}
*/
import "C"

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"time"
	"unsafe"
)

func u16(n int) []byte { return []byte{byte(n >> 8), byte(n)} }
func u24(n int) []byte { return []byte{byte(n >> 16), byte(n >> 8), byte(n)} }
func handshake(kind byte, body []byte) []byte {
	return append(append([]byte{kind}, u24(len(body))...), body...)
}
func record(kind byte, body []byte) []byte {
	return append(append([]byte{kind, 3, 3}, u16(len(body))...), body...)
}
func readRecord(c net.Conn) (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(c, header); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(header[3:]))
	if n > 18432 {
		return 0, nil, errors.New("oversized TLS record")
	}
	data := make([]byte, n)
	_, err := io.ReadFull(c, data)
	return header[0], data, err
}
func prf(secret []byte, label string, seed []byte, n int) []byte {
	seed = append([]byte(label), seed...)
	a, out := seed, []byte{}
	for len(out) < n {
		m := hmac.New(sha256.New, secret)
		m.Write(a)
		a = m.Sum(nil)
		m = hmac.New(sha256.New, secret)
		m.Write(a)
		m.Write(seed)
		out = append(out, m.Sum(nil)...)
	}
	return out[:n]
}
func makeAEAD(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}
func additional(seq uint64, kind byte, size int) []byte {
	a := make([]byte, 13)
	binary.BigEndian.PutUint64(a, seq)
	a[8], a[9], a[10] = kind, 3, 3
	binary.BigEndian.PutUint16(a[11:], uint16(size))
	return a
}
func seal(aead cipher.AEAD, salt []byte, seq uint64, kind byte, plain []byte) []byte {
	explicit := make([]byte, 8)
	binary.BigEndian.PutUint64(explicit, seq)
	nonce := append(append([]byte{}, salt...), explicit...)
	return append(explicit, aead.Seal(nil, nonce, plain, additional(seq, kind, len(plain)))...)
}
func open(aead cipher.AEAD, salt []byte, seq uint64, kind byte, data []byte) ([]byte, error) {
	if len(data) < 8+aead.Overhead() {
		return nil, errors.New("short GCM record")
	}
	nonce := append(append([]byte{}, salt...), data[:8]...)
	return aead.Open(nil, nonce, data[8:], additional(seq, kind, len(data)-8-aead.Overhead()))
}

func parseHello(data []byte, evidence map[string]any) ([]byte, bool, error) {
	if len(data) < 42 || data[0] != 1 || data[4] != 3 || data[5] != 3 {
		return nil, false, errors.New("expected TLS 1.2 ClientHello")
	}
	randomBytes := append([]byte{}, data[6:38]...)
	pos := 39 + int(data[38])
	if pos+2 > len(data) {
		return nil, false, errors.New("short session")
	}
	n := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2
	if pos+n > len(data) || n%2 != 0 {
		return nil, false, errors.New("bad cipher list")
	}
	offered, reneg := false, false
	for i := pos; i < pos+n; i += 2 {
		id := binary.BigEndian.Uint16(data[i:])
		offered = offered || id == 0xc02f
		reneg = reneg || id == 0x00ff
	}
	if !offered {
		return nil, false, errors.New("ECDHE-RSA AES128-GCM not offered")
	}
	pos += n
	if pos >= len(data) {
		return nil, false, errors.New("missing compression")
	}
	pos += 1 + int(data[pos])
	if pos+2 > len(data) {
		return nil, false, errors.New("missing extensions")
	}
	n = int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2
	if pos+n != len(data) {
		return nil, false, errors.New("bad extension length")
	}
	formats, groups := []int{}, []int{}
	for pos < len(data) {
		if pos+4 > len(data) {
			return nil, false, errors.New("short extension")
		}
		id, size := binary.BigEndian.Uint16(data[pos:]), int(binary.BigEndian.Uint16(data[pos+2:]))
		pos += 4
		if pos+size > len(data) {
			return nil, false, errors.New("bad extension")
		}
		body := data[pos : pos+size]
		if id == 11 {
			if len(body) == 0 || int(body[0]) != len(body)-1 {
				return nil, false, errors.New("bad point format vector")
			}
			for _, value := range body[1:] {
				formats = append(formats, int(value))
			}
		}
		if id == 10 {
			if len(body) < 2 || int(binary.BigEndian.Uint16(body)) != len(body)-2 || len(body)%2 != 0 {
				return nil, false, errors.New("bad group vector")
			}
			for i := 2; i+1 < len(body); i += 2 {
				groups = append(groups, int(binary.BigEndian.Uint16(body[i:])))
			}
		}
		if id == 65281 {
			reneg = true
		}
		pos += size
	}
	formatOffered, groupOffered := false, false
	for _, format := range formats {
		formatOffered = formatOffered || format == 2
	}
	for _, group := range groups {
		groupOffered = groupOffered || group == 10
	}
	evidence["outgoing_point_formats"], evidence["outgoing_groups"] = formats, groups
	evidence["compressed_char2_offered"], evidence["selected_group_offered"] = formatOffered, groupOffered
	return randomBytes, reneg, nil
}

func serve(c net.Conn, certificate tls.Certificate, mode string, evidence map[string]any) error {
	c.SetDeadline(time.Now().Add(20 * time.Second))
	kind, ch, err := readRecord(c)
	if err != nil {
		return err
	}
	if kind != 22 {
		return errors.New("missing ClientHello")
	}
	clientRandom, reneg, err := parseHello(ch, evidence)
	if err != nil {
		return err
	}
	if mode != "group-not-offered" && evidence["selected_group_offered"] != true {
		return errors.New("sect283r1 was not preserved")
	}
	if mode != "format-not-offered" && evidence["compressed_char2_offered"] != true {
		return errors.New("compressed_char2 was not preserved")
	}
	serverRandom := make([]byte, 32)
	if _, err = rand.Read(serverRandom); err != nil {
		return err
	}
	extensions := []byte{}
	if reneg {
		extensions = append(extensions, 255, 1, 0, 1, 0)
	}
	sh := append([]byte{3, 3}, serverRandom...)
	sh = append(sh, 0, 0xc0, 0x2f, 0)
	sh = append(sh, u16(len(extensions))...)
	sh = append(sh, extensions...)
	transcript := append([]byte{}, ch...)
	chain := []byte{}
	for index, cert := range certificate.Certificate {
		der := append([]byte{}, cert...)
		if mode == "bad-certificate" && index == 0 {
			der[len(der)-1] ^= 1
		}
		chain = append(chain, u24(len(der))...)
		chain = append(chain, der...)
	}
	key, ok := certificate.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return errors.New("RSA key required")
	}
	ecdhe := C.char2_key()
	if ecdhe == nil {
		return errors.New("OpenSSL sect283r1 key generation failed")
	}
	defer C.EC_KEY_free(ecdhe)
	point := make([]byte, 73)
	compressed := C.int(1)
	if mode == "uncompressed" {
		compressed = 0
	}
	size := int(C.char2_public(ecdhe, compressed, (*C.uchar)(unsafe.Pointer(&point[0]))))
	if size != 37 && size != 73 {
		return errors.New("bad OpenSSL sect283r1 point size")
	}
	point = point[:size]
	switch mode {
	case "malformed":
		point = point[:len(point)-1]
	case "off-curve":
		if C.char2_off_curve() != 1 {
			return errors.New("off-curve fixture unexpectedly valid")
		}
		point = make([]byte, 73)
		point[0] = 4
		evidence["fixture_off_curve_confirmed"] = true
	case "small-subgroup":
		if C.char2_order_two() != 1 {
			return errors.New("independent order-two fixture validation failed")
		}
		point = make([]byte, 37)
		point[0] = 2
		evidence["fixture_order_two_confirmed"] = true
	case "mixed-subgroup":
		point = make([]byte, 37)
		if C.char2_mixed_subgroup(ecdhe, (*C.uchar)(unsafe.Pointer(&point[0]))) != 37 {
			return errors.New("independent mixed-subgroup fixture validation failed")
		}
		evidence["fixture_mixed_subgroup_confirmed"] = true
	case "infinity":
		point = []byte{0}
	}
	params := append([]byte{3, 0, 10, byte(len(point))}, point...)
	signed := append(append(append([]byte{}, clientRandom...), serverRandom...), params...)
	digest := sha256.Sum256(signed)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return err
	}
	if mode == "bad-handshake-signature" {
		signature[len(signature)-1] ^= 1
	}
	ske := append(append(append([]byte{}, params...), 4, 1), u16(len(signature))...)
	ske = append(ske, signature...)
	messages := [][]byte{handshake(2, sh), handshake(11, append(u24(len(chain)), chain...)), handshake(12, ske), handshake(14, nil)}
	// One TLS record removes a race in certificate-negative cases where the
	// client can reject Certificate before the peer writes ServerKeyExchange.
	flight := []byte{}
	for _, msg := range messages {
		flight = append(flight, msg...)
		transcript = append(transcript, msg...)
	}
	if _, err = c.Write(record(22, flight)); err != nil {
		return err
	}
	evidence["server_group"], evidence["server_point_prefix"], evidence["server_point_bytes"] = 10, int(point[0]), len(point)
	evidence["server_key_sent"] = true
	kind, cke, err := readRecord(c)
	if err != nil {
		return err
	}
	positive := mode == "compressed" || mode == "uncompressed"
	if kind == 21 {
		if len(cke) != 2 {
			return errors.New("malformed client alert")
		}
		evidence["client_alert"] = int(cke[1])
		evidence["rejected_before_client_key_exchange"] = true
		if !positive {
			evidence["negative_rejected"] = true
			return nil
		}
		return errors.New("valid sect283r1 point rejected")
	}
	if !positive {
		return errors.New("negative server flight accepted")
	}
	if kind != 22 || len(cke) < 6 || cke[0] != 16 {
		return errors.New("expected ECDHE ClientKeyExchange")
	}
	n := int(cke[4])
	if n != len(cke)-5 {
		return errors.New("bad ECDHE CKE length")
	}
	evidence["client_point_prefix"], evidence["client_point_bytes"] = int(cke[5]), n
	premaster := make([]byte, 36)
	n = int(C.char2_secret(ecdhe, (*C.uchar)(unsafe.Pointer(&cke[5])), C.size_t(len(cke)-5), (*C.uchar)(unsafe.Pointer(&premaster[0]))))
	if n != 36 {
		return errors.New("independent sect283r1 ECDH failed")
	}
	transcript = append(transcript, cke...)
	master := prf(premaster, "master secret", append(append([]byte{}, clientRandom...), serverRandom...), 48)
	keys := prf(master, "key expansion", append(append([]byte{}, serverRandom...), clientRandom...), 40)
	clientAEAD, err := makeAEAD(keys[:16])
	if err != nil {
		return err
	}
	serverAEAD, err := makeAEAD(keys[16:32])
	if err != nil {
		return err
	}
	clientSalt, serverSalt := keys[32:36], keys[36:40]
	kind, data, err := readRecord(c)
	if err != nil {
		return err
	}
	if kind != 20 || !bytes.Equal(data, []byte{1}) {
		return errors.New("expected CCS")
	}
	kind, data, err = readRecord(c)
	if err != nil {
		return err
	}
	if kind != 22 {
		return errors.New("expected encrypted Finished")
	}
	finished, err := open(clientAEAD, clientSalt, 0, kind, data)
	if err != nil {
		return err
	}
	h := sha256.Sum256(transcript)
	expected := handshake(20, prf(master, "client finished", h[:], 12))
	if !hmac.Equal(finished, expected) {
		return errors.New("bad client Finished")
	}
	transcript = append(transcript, finished...)
	evidence["client_finished_verified"] = true
	if _, err = c.Write(record(20, []byte{1})); err != nil {
		return err
	}
	h = sha256.Sum256(transcript)
	finished = handshake(20, prf(master, "server finished", h[:], 12))
	if _, err = c.Write(record(22, seal(serverAEAD, serverSalt, 0, 22, finished))); err != nil {
		return err
	}
	kind, data, err = readRecord(c)
	if err != nil {
		return err
	}
	if kind != 23 {
		return errors.New("expected encrypted HTTP")
	}
	request, err := open(clientAEAD, clientSalt, 1, kind, data)
	if err != nil {
		return err
	}
	if !bytes.Contains(request, []byte("Cookie: sid=from_B")) {
		return errors.New("missing preserved cookie")
	}
	port := c.LocalAddr().(*net.TCPAddr).Port
	if !bytes.Contains(request, []byte(fmt.Sprintf("Host: a.test:%d", port))) {
		return errors.New("authority not rewritten")
	}
	evidence["http_request_received"], evidence["cookie_preserved"], evidence["authority_rewritten"] = true, true, true
	body := []byte("CHAR2_OK")
	response := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(body)))
	_, err = c.Write(record(23, seal(serverAEAD, serverSalt, 1, 23, append(response, body...))))
	if err != nil {
		return err
	}
	_, err = c.Write(record(21, seal(serverAEAD, serverSalt, 2, 21, []byte{1, 0})))
	return err
}

func main() {
	certPath := flag.String("cert", "", "synthetic chain")
	keyPath := flag.String("key", "", "synthetic key")
	mode := flag.String("mode", "compressed", "controlled test case")
	flag.Parse()
	certificate, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		panic(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	fmt.Printf("{\"port\":%d}\n", listener.Addr().(*net.TCPAddr).Port)
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Second))
	c, err := listener.Accept()
	evidence := map[string]any{"mode": *mode, "curve": "sect283r1", "independent_crypto": C.GoString(C.OpenSSL_version(0))}
	if err == nil {
		err = serve(c, certificate, *mode, evidence)
		c.Close()
	}
	if err != nil {
		evidence["error"] = err.Error()
	}
	encoded, _ := json.Marshal(evidence)
	fmt.Println(string(encoded))
}
