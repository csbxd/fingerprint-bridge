// Independent crypto/tls peer for the targeted hybrid-group lab (Go >= 1.26).
// This does not replace or change the default clients in the fingerprint matrix.
package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"
)

func main() {
	mode := flag.String("mode", "client", "client or server")
	group := flag.Int("group", 4587, "hybrid wire group ID")
	address := flag.String("address", "127.0.0.1:0", "loopback address")
	host := flag.String("host", "b.test", "verified hostname")
	authority := flag.String("authority", "", "expected HTTP Host at the origin")
	ca := flag.String("ca", "", "CA PEM")
	cert := flag.String("cert", "", "server certificate PEM")
	key := flag.String("key", "", "server key PEM")
	hrr := flag.Bool("hrr", false, "offer X25519MLKEM768 first, forcing origin HRR")
	flag.Parse()
	if *group != 4587 && *group != 4589 {
		panic("unexpected hybrid group")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.CurveID(*group)}, NextProtos: []string{"http/1.1"}}
	result := map[string]any{"go": runtime.Version(), "mode": *mode, "group": *group,
		"handshake": false, "http": false}
	var err error
	if *mode == "server" {
		err = server(config, *address, *cert, *key, *authority, result)
	} else if *mode == "client" {
		if *hrr {
			config.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768, tls.CurveID(*group)}
		}
		err = client(config, *address, *host, *ca, result)
	} else {
		panic("unexpected mode")
	}
	if err != nil {
		result["error"] = err.Error()
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		panic(err)
	}
	if err != nil {
		os.Exit(1)
	}
}

func server(config *tls.Config, address, cert, key, authority string, result map[string]any) error {
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return err
	}
	config.Certificates = []tls.Certificate{pair}
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	fmt.Println(listener.Addr().(*net.TCPAddr).Port)
	raw, err := listener.Accept()
	if err != nil {
		return err
	}
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	conn := tls.Server(raw, config)
	if err := conn.Handshake(); err != nil {
		return err
	}
	result["handshake"] = true
	result["tls_version"] = conn.ConnectionState().Version
	result["negotiated_group"] = uint16(conn.ConnectionState().CurveID)
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return err
	}
	defer req.Body.Close()
	if req.Host != authority || req.Header.Get("Cookie") != "sid=from_B" {
		return fmt.Errorf("unexpected Host or B cookie: %q / %q", req.Host, req.Header.Get("Cookie"))
	}
	result["http"] = true
	_, err = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nhybrid-ok")
	return err
}

func client(config *tls.Config, address, host, ca string, result map[string]any) error {
	pem, err := os.ReadFile(ca)
	if err != nil {
		return err
	}
	config.RootCAs = x509.NewCertPool()
	if !config.RootCAs.AppendCertsFromPEM(pem) {
		return fmt.Errorf("invalid CA")
	}
	config.ServerName = host
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp4", address, config)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	result["handshake"] = true
	result["tls_version"] = conn.ConnectionState().Version
	result["negotiated_group"] = uint16(conn.ConnectionState().CurveID)
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(conn, "GET /hybrid HTTP/1.1\r\nHost: %s:%s\r\nCookie: sid=from_B\r\nConnection: close\r\n\r\n", host, port)
	if err != nil {
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode != 200 || string(body) != "hybrid-ok" {
		return fmt.Errorf("unexpected HTTP response")
	}
	result["http"] = true
	return nil
}
