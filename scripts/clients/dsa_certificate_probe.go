// Independent loopback TLS server for certificate verification tests.
// The RSA leaf is signed by an OpenSSL-generated DSA CA; B verifies that signature.
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

func main() {
	certPath := flag.String("cert", "", "synthetic leaf certificate")
	keyPath := flag.String("key", "", "synthetic RSA leaf key")
	version := flag.Uint("version", 0, "TLS wire version")
	flag.Parse()
	if *version != tls.VersionTLS12 && *version != tls.VersionTLS13 {
		panic("invalid TLS version")
	}
	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		panic(err)
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	listener.SetDeadline(time.Now().Add(20 * time.Second))
	port := listener.Addr().(*net.TCPAddr).Port
	encoder := json.NewEncoder(os.Stdout)
	encoder.Encode(map[string]any{"port": port})
	result := map[string]any{"handshake": false, "requests": []string{}}
	defer func() { encoder.Encode(result) }()
	raw, err := listener.Accept()
	if err != nil {
		result["error"] = err.Error()
		return
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(15 * time.Second))
	conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: uint16(*version), MaxVersion: uint16(*version), NextProtos: []string{"http/1.1"}})
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		result["error"] = err.Error()
		return
	}
	result["handshake"] = true
	result["tls_version"] = conn.ConnectionState().Version
	reader := bufio.NewReader(conn)
	requests := []string{}
	for i := 0; i < 2; i++ {
		var head strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				result["error"] = err.Error()
				return
			}
			head.WriteString(line)
			if line == "\r\n" {
				break
			}
		}
		if strings.HasPrefix(head.String(), "POST ") {
			body := make([]byte, 7)
			if _, err := io.ReadFull(reader, body); err != nil {
				result["error"] = err.Error()
				return
			}
			if string(body) != "ab\x00c\xffde" {
				result["error"] = "request body changed"
				return
			}
		}
		requests = append(requests, head.String())
		result["requests"] = requests
		response := fmt.Sprintf("HTTP/1.1 200 OK\r\nSet-Cookie: sid=from_A; Domain=a.test; Path=/; Secure; HttpOnly; SameSite=Lax\r\nSet-Cookie: hostonly=yes; Secure\r\nLocation: https://a.test:%d/next%%2Fpage?q=1\r\nContent-Length: 7\r\n\r\na\x00b\xffcde", port)
		if _, err := io.WriteString(conn, response); err != nil {
			result["error"] = err.Error()
			return
		}
	}
}
