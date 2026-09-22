// Independent loopback-only TLS 1.2 RSA/AES-GCM + RFC 6961 fixture. Go's
// crypto primitives implement the records; the bridge backend is not linked.
package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
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
	"os"
	"time"
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
	if _, err := io.ReadFull(c, header); err != nil { return 0, nil, err }
	n := int(binary.BigEndian.Uint16(header[3:]))
	if n > 18432 { return 0, nil, errors.New("oversized TLS record") }
	data := make([]byte, n)
	_, err := io.ReadFull(c, data)
	return header[0], data, err
}
func prf(secret []byte, label string, seed []byte, n int) []byte {
	seed = append([]byte(label), seed...)
	a, out := seed, []byte{}
	for len(out) < n {
		m := hmac.New(sha256.New, secret); m.Write(a); a = m.Sum(nil)
		m = hmac.New(sha256.New, secret); m.Write(a); m.Write(seed)
		out = append(out, m.Sum(nil)...)
	}
	return out[:n]
}
func makeAEAD(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key); if err != nil { return nil, err }
	return cipher.NewGCM(b)
}
func additional(seq uint64, kind byte, size int) []byte {
	a := make([]byte, 13); binary.BigEndian.PutUint64(a, seq)
	a[8], a[9], a[10] = kind, 3, 3
	binary.BigEndian.PutUint16(a[11:], uint16(size)); return a
}
func seal(aead cipher.AEAD, salt []byte, seq uint64, kind byte, plain []byte) []byte {
	explicit := make([]byte, 8); binary.BigEndian.PutUint64(explicit, seq)
	nonce := append(append([]byte{}, salt...), explicit...)
	return append(explicit, aead.Seal(nil, nonce, plain, additional(seq, kind, len(plain)))...)
}
func open(aead cipher.AEAD, salt []byte, seq uint64, kind byte, data []byte) ([]byte, error) {
	if len(data) < 8+aead.Overhead() { return nil, errors.New("short GCM record") }
	nonce := append(append([]byte{}, salt...), data[:8]...)
	return aead.Open(nil, nonce, data[8:], additional(seq, kind, len(data)-8-aead.Overhead()))
}

func parseHello(data []byte) ([]byte, bool, error) {
	if len(data) < 42 || data[0] != 1 || data[4] != 3 || data[5] != 3 {
		return nil, false, errors.New("expected TLS 1.2 ClientHello")
	}
	randomBytes := append([]byte{}, data[6:38]...)
	pos := 38 + 1 + int(data[38])
	if pos+2 > len(data) { return nil, false, errors.New("short session") }
	n := int(binary.BigEndian.Uint16(data[pos:])); pos += 2
	if pos+n > len(data) || n%2 != 0 { return nil, false, errors.New("bad cipher list") }
	offered, reneg := false, false
	for i := pos; i < pos+n; i += 2 {
		id := binary.BigEndian.Uint16(data[i:]); offered = offered || id == 0xc02f; reneg = reneg || id == 0x00ff
	}
	if !offered { return nil, false, errors.New("ECDHE-RSA AES128-GCM not offered") }
	pos += n
	if pos >= len(data) { return nil, false, errors.New("missing compression") }
	pos += 1 + int(data[pos])
	if pos+2 > len(data) { return nil, false, errors.New("missing extensions") }
	n = int(binary.BigEndian.Uint16(data[pos:])); pos += 2
	if pos+n != len(data) { return nil, false, errors.New("bad extension length") }
	found := false
	javaBody := []byte{0, 7, 2, 0, 4, 0, 0, 0, 0}
	for pos < len(data) {
		if pos+4 > len(data) { return nil, false, errors.New("short extension") }
		id, size := binary.BigEndian.Uint16(data[pos:]), int(binary.BigEndian.Uint16(data[pos+2:])); pos += 4
		if pos+size > len(data) { return nil, false, errors.New("bad extension") }
		if id == 17 { found = bytes.Equal(data[pos:pos+size], javaBody) }
		if id == 65281 { reneg = true }
		pos += size
	}
	if !found { return nil, false, errors.New("exact status_request_v2 body not offered") }
	return randomBytes, reneg, nil
}

func serve(c net.Conn, certificate tls.Certificate, response []byte, mode string, evidence map[string]any) error {
	c.SetDeadline(time.Now().Add(20 * time.Second))
	kind, ch, err := readRecord(c); if err != nil { return err }
	if kind != 22 { return errors.New("missing ClientHello") }
	clientRandom, reneg, err := parseHello(ch); if err != nil { return err }
	evidence["exact_status_request_v2_offered"] = true
	serverRandom := make([]byte, 32); if _, err = rand.Read(serverRandom); err != nil { return err }
	extensions := []byte{0, 17, 0, 0}
	if reneg { extensions = append(extensions, 255, 1, 0, 1, 0) }
	sh := append([]byte{3, 3}, serverRandom...); sh = append(sh, 0, 0xc0, 0x2f, 0)
	sh = append(sh, u16(len(extensions))...); sh = append(sh, extensions...)
	transcript := append([]byte{}, ch...)
	chain := []byte{}
	for _, der := range certificate.Certificate { chain = append(chain, u24(len(der))...); chain = append(chain, der...) }
	key, ok := certificate.PrivateKey.(*rsa.PrivateKey); if !ok { return errors.New("RSA key required") }
	ecdhe, err := ecdh.P256().GenerateKey(rand.Reader); if err != nil { return err }
	params := append([]byte{3, 0, 23, byte(len(ecdhe.PublicKey().Bytes()))}, ecdhe.PublicKey().Bytes()...)
	signed := append(append(append([]byte{}, clientRandom...), serverRandom...), params...)
	digest := sha256.Sum256(signed)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:]); if err != nil { return err }
	ske := append(append(append([]byte{}, params...), 4, 1), u16(len(signature))...)
	ske = append(ske, signature...)
	messages := [][]byte{handshake(2, sh), handshake(11, append(u24(len(chain)), chain...)), handshake(12, ske)}
	if mode != "omitted" {
		staple := append([]byte{}, response...)
		if mode == "bad-signature" { staple[len(staple)-1] ^= 1 }
		list := append(u24(len(staple)), staple...)
		status := append([]byte{2}, u24(len(list))...); status = append(status, list...)
		if mode == "malformed-list" { status[3]++ }
		messages = append(messages, handshake(22, status))
	}
	messages = append(messages, handshake(14, nil))
	for _, msg := range messages {
		if _, err = c.Write(record(22, msg)); err != nil { return err }
		transcript = append(transcript, msg...)
	}
	evidence["negotiated_status_request_v2"] = true
	kind, cke, err := readRecord(c)
	if err != nil { return err }
	if kind == 21 { evidence["client_alert"] = int(cke[len(cke)-1]); return errors.New("client rejected status response") }
	if kind != 22 || len(cke) < 6 || cke[0] != 16 { return errors.New("expected ECDHE ClientKeyExchange") }
	n := int(cke[4]); if n != len(cke)-5 { return errors.New("bad ECDHE CKE length") }
	peer, err := ecdh.P256().NewPublicKey(cke[5:]); if err != nil { return err }
	premaster, err := ecdhe.ECDH(peer); if err != nil { return err }
	transcript = append(transcript, cke...)
	master := prf(premaster, "master secret", append(append([]byte{}, clientRandom...), serverRandom...), 48)
	keys := prf(master, "key expansion", append(append([]byte{}, serverRandom...), clientRandom...), 40)
	clientAEAD, err := makeAEAD(keys[:16]); if err != nil { return err }
	serverAEAD, err := makeAEAD(keys[16:32]); if err != nil { return err }
	clientSalt, serverSalt := keys[32:36], keys[36:40]
	kind, data, err := readRecord(c); if err != nil { return err }
	if kind != 20 || !bytes.Equal(data, []byte{1}) { return errors.New("expected CCS") }
	kind, data, err = readRecord(c); if err != nil { return err }
	finished, err := open(clientAEAD, clientSalt, 0, kind, data); if err != nil { return err }
	h := sha256.Sum256(transcript); expected := handshake(20, prf(master, "client finished", h[:], 12))
	if !hmac.Equal(finished, expected) { return errors.New("bad client Finished") }
	transcript = append(transcript, finished...); evidence["client_finished_verified"] = true
	if _, err = c.Write(record(20, []byte{1})); err != nil { return err }
	h = sha256.Sum256(transcript); finished = handshake(20, prf(master, "server finished", h[:], 12))
	if _, err = c.Write(record(22, seal(serverAEAD, serverSalt, 0, 22, finished))); err != nil { return err }
	kind, data, err = readRecord(c); if err != nil { return err }
	request, err := open(clientAEAD, clientSalt, 1, kind, data); if err != nil { return err }
	if kind != 23 || !bytes.Contains(request, []byte("Cookie: sid=from_B")) { return errors.New("missing preserved cookie") }
	port := c.LocalAddr().(*net.TCPAddr).Port
	if !bytes.Contains(request, []byte(fmt.Sprintf("Host: a.test:%d", port))) { return errors.New("authority not rewritten") }
	evidence["http_request_received"], evidence["cookie_preserved"], evidence["authority_rewritten"] = true, true, true
	body := []byte("STATUS_V2_OK")
	responseHTTP := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nSet-Cookie: sid=from_A; Domain=a.test; Secure\r\nLocation: https://a.test:%d/next\r\nConnection: close\r\n\r\n", len(body), port))
	responseHTTP = append(responseHTTP, body...)
	_, err = c.Write(record(23, seal(serverAEAD, serverSalt, 1, 23, responseHTTP)))
	return err
}

func main() {
	certPath := flag.String("cert", "", "synthetic chain")
	keyPath := flag.String("key", "", "synthetic key")
	ocspPath := flag.String("ocsp", "", "synthetic OCSP response")
	mode := flag.String("mode", "valid", "valid, revoked, bad-signature, malformed-list, omitted")
	flag.Parse()
	certificate, err := tls.LoadX509KeyPair(*certPath, *keyPath); if err != nil { panic(err) }
	response, err := os.ReadFile(*ocspPath); if err != nil { panic(err) }
	listener, err := net.Listen("tcp4", "127.0.0.1:0"); if err != nil { panic(err) }
	defer listener.Close(); fmt.Printf("{\"port\":%d}\n", listener.Addr().(*net.TCPAddr).Port)
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Second))
	c, err := listener.Accept(); evidence := map[string]any{"mode": *mode}
	if err == nil { err = serve(c, certificate, response, *mode, evidence); c.Close() }
	if err != nil { evidence["error"] = err.Error() }
	encoded, _ := json.Marshal(evidence); fmt.Println(string(encoded))
}
