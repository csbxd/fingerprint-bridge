// Independent loopback-only TLS 1.2 RSA/3DES + RFC 7366 fixture. Go's standard
// crypto primitives implement the records; the bridge backend is not linked.
// The fixture uses fresh temporary certificates and never logs key material.
package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"strings"
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
	a := seed
	out := []byte{}
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
func mac(key []byte, seq uint64, kind byte, fragment []byte) []byte {
	ad := make([]byte, 13)
	binary.BigEndian.PutUint64(ad, seq)
	ad[8] = kind
	ad[9] = 3
	ad[10] = 3
	binary.BigEndian.PutUint16(ad[11:], uint16(len(fragment)))
	h := hmac.New(sha1.New, key)
	h.Write(ad)
	h.Write(fragment)
	return h.Sum(nil)
}
func seal(key, mkey []byte, seq uint64, kind byte, plain []byte, mode string) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	pad := 8 - len(plain)%8
	body := append(append([]byte{}, plain...), bytes.Repeat([]byte{byte(pad - 1)}, pad)...)
	if mode == "bad-padding" {
		body[len(body)-1] ^= 0x80
	}
	iv := make([]byte, 8)
	if _, err = rand.Read(iv); err != nil {
		return nil, err
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(body, body)
	fragment := append(iv, body...)
	out := append(fragment, mac(mkey, seq, kind, fragment)...)
	switch mode {
	case "bad-iv":
		out[0] ^= 1
	case "bad-ciphertext":
		out[8] ^= 1
	case "bad-mac":
		out[len(out)-1] ^= 1
	case "bad-truncated":
		out = out[:len(out)-1]
	}
	return out, nil
}
func open(key, mkey []byte, seq uint64, kind byte, data []byte) ([]byte, error) {
	if len(data) < 36 {
		return nil, errors.New("short EtM record")
	}
	fragment, tag := data[:len(data)-20], data[len(data)-20:]
	if !hmac.Equal(tag, mac(mkey, seq, kind, fragment)) {
		return nil, errors.New("bad EtM MAC")
	}
	body := append([]byte{}, fragment[8:]...)
	if len(body)%8 != 0 {
		return nil, errors.New("bad CBC length")
	}
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	cipher.NewCBCDecrypter(block, fragment[:8]).CryptBlocks(body, body)
	pad := int(body[len(body)-1]) + 1
	if pad > len(body) {
		return nil, errors.New("bad CBC padding length")
	}
	if !bytes.Equal(body[len(body)-pad:], bytes.Repeat([]byte{byte(pad - 1)}, pad)) {
		return nil, errors.New("bad CBC padding")
	}
	return body[:len(body)-pad], nil
}
func parseHello(data []byte) (random []byte, reneg bool, err error) {
	if len(data) < 42 || data[0] != 1 || data[4] != 3 || data[5] != 3 {
		return nil, false, errors.New("expected TLS 1.2 ClientHello")
	}
	random = append([]byte{}, data[6:38]...)
	pos := 38 + 1 + int(data[38])
	if pos+2 > len(data) {
		return nil, false, errors.New("short ClientHello session")
	}
	n := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2
	if pos+n > len(data) || n%2 != 0 {
		return nil, false, errors.New("bad cipher list")
	}
	offered := false
	for i := pos; i < pos+n; i += 2 {
		id := binary.BigEndian.Uint16(data[i:])
		offered = offered || id == 10
		reneg = reneg || id == 255
	}
	pos += n
	if !offered {
		return nil, false, errors.New("RSA 3DES not offered")
	}
	if pos >= len(data) {
		return nil, false, errors.New("short compression list")
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
	etm := false
	for pos < len(data) {
		if pos+4 > len(data) {
			return nil, false, errors.New("short extension")
		}
		id := binary.BigEndian.Uint16(data[pos:])
		size := int(binary.BigEndian.Uint16(data[pos+2:]))
		pos += 4
		if pos+size > len(data) {
			return nil, false, errors.New("bad extension")
		}
		etm = etm || (id == 22 && size == 0)
		reneg = reneg || id == 65281
		pos += size
	}
	if !etm {
		return nil, false, errors.New("EtM not offered")
	}
	return random, reneg, nil
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
	clientRandom, reneg, err := parseHello(ch)
	if err != nil {
		return err
	}
	evidence["client_offered_3des_etm"] = true
	serverRandom := make([]byte, 32)
	if _, err = rand.Read(serverRandom); err != nil {
		return err
	}
	extensions := []byte{0, 22, 0, 0}
	if reneg {
		extensions = append(extensions, 255, 1, 0, 1, 0)
	}
	sh := append([]byte{3, 3}, serverRandom...)
	sh = append(sh, 0, 0, 10, 0)
	sh = append(sh, u16(len(extensions))...)
	sh = append(sh, extensions...)
	transcript := append([]byte{}, ch...)
	chain := []byte{}
	for _, der := range certificate.Certificate {
		chain = append(chain, u24(len(der))...)
		chain = append(chain, der...)
	}
	for _, msg := range [][]byte{handshake(2, sh), handshake(11, append(u24(len(chain)), chain...)), handshake(14, nil)} {
		if _, err = c.Write(record(22, msg)); err != nil {
			return err
		}
		transcript = append(transcript, msg...)
	}
	evidence["selected_cipher"] = 10
	evidence["negotiated_etm"] = true
	kind, cke, err := readRecord(c)
	if err != nil {
		return err
	}
	if kind != 22 || len(cke) < 6 || cke[0] != 16 {
		return errors.New("expected RSA ClientKeyExchange")
	}
	encryptedLength := int(binary.BigEndian.Uint16(cke[4:6]))
	if encryptedLength != len(cke)-6 {
		return errors.New("invalid RSA premaster ciphertext length")
	}
	key, ok := certificate.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return errors.New("RSA certificate required")
	}
	premaster := make([]byte, 48)
	if _, err = rand.Read(premaster); err != nil {
		return err
	}
	if err = rsa.DecryptPKCS1v15SessionKey(rand.Reader, key, cke[6:], premaster); err != nil {
		return err
	}
	if premaster[0] != 3 || premaster[1] != 3 {
		return errors.New("bad premaster version")
	}
	transcript = append(transcript, cke...)
	seed := append(append([]byte{}, clientRandom...), serverRandom...)
	master := prf(premaster, "master secret", seed, 48)
	seed = append(append([]byte{}, serverRandom...), clientRandom...)
	keys := prf(master, "key expansion", seed, 88)
	clientMAC, serverMAC, clientKey, serverKey := keys[:20], keys[20:40], keys[40:64], keys[64:88]
	kind, data, err := readRecord(c)
	if err != nil {
		return err
	}
	if kind != 20 || !bytes.Equal(data, []byte{1}) {
		return errors.New("expected ChangeCipherSpec")
	}
	kind, data, err = readRecord(c)
	if err != nil {
		return err
	}
	if kind != 22 {
		return errors.New("expected encrypted Finished")
	}
	finished, err := open(clientKey, clientMAC, 0, kind, data)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(transcript)
	expected := handshake(20, prf(master, "client finished", hash[:], 12))
	if !hmac.Equal(finished, expected) {
		return errors.New("client Finished verification failed")
	}
	evidence["client_finished_verified"] = true
	transcript = append(transcript, finished...)
	if _, err = c.Write(record(20, []byte{1})); err != nil {
		return err
	}
	hash = sha256.Sum256(transcript)
	finished = handshake(20, prf(master, "server finished", hash[:], 12))
	sealed, err := seal(serverKey, serverMAC, 0, 22, finished, "")
	if err != nil {
		return err
	}
	if _, err = c.Write(record(22, sealed)); err != nil {
		return err
	}
	request := []byte{}
	for seq := uint64(1); len(request) < 65536; seq++ {
		kind, data, err = readRecord(c)
		if err != nil {
			return err
		}
		plain, err := open(clientKey, clientMAC, seq, kind, data)
		if err != nil {
			return err
		}
		if kind != 23 {
			return errors.New("expected HTTP application data")
		}
		request = append(request, plain...)
		if bytes.Contains(request, []byte("\r\n\r\n")) {
			break
		}
	}
	evidence["http_request_received"] = true
	evidence["cookie_preserved"] = bytes.Contains(request, []byte("Cookie: sid=from_B; flag=yes\r\n"))
	evidence["authority_rewritten"] = bytes.Contains(request, []byte(fmt.Sprintf("Host: a.test:%d\r\n", c.LocalAddr().(*net.TCPAddr).Port)))
	if evidence["cookie_preserved"] != true || evidence["authority_rewritten"] != true {
		return errors.New("HTTP authority/cookie mismatch")
	}
	payload := append(bytes.Repeat([]byte("3DES-etm\x00\xff"), 97), []byte("done")...)
	response := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nSet-Cookie: sid=from_A; Domain=a.test; Secure\r\nLocation: https://a.test:%d/next\r\n\r\n", len(payload), c.LocalAddr().(*net.TCPAddr).Port))
	response = append(response, payload...)
	sealed, err = seal(serverKey, serverMAC, 1, 23, response, mode)
	if err != nil {
		return err
	}
	if _, err = c.Write(record(23, sealed)); err != nil {
		return err
	}
	evidence["mutation"] = mode
	evidence["authenticated_bad_padding"] = mode == "bad-padding"
	if !strings.HasPrefix(mode, "bad-") {
		sealed, err = seal(serverKey, serverMAC, 2, 21, []byte{1, 0}, "")
		if err != nil {
			return err
		}
		_, err = c.Write(record(21, sealed))
	}
	return err
}
func main() {
	cert := flag.String("cert", "", "synthetic certificate")
	key := flag.String("key", "", "synthetic RSA key")
	mode := flag.String("mode", "valid", "record mode")
	flag.Parse()
	certificate, err := tls.LoadX509KeyPair(*cert, *key)
	if err != nil {
		panic(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	// Only public endpoint and verification outcomes go to stdout.
	fmt.Printf("{\"port\":%d}\n", listener.Addr().(*net.TCPAddr).Port)
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Second))
	c, err := listener.Accept()
	evidence := map[string]any{"mode": *mode}
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
