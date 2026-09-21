//go:build go1.26

// mldsa_probe provides an independent Go TLS 1.3 peer for ML-DSA tests.
package main

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type result struct {
	Address    string `json:"address,omitempty"`
	CA         string `json:"ca,omitempty"`
	Handshake  bool   `json:"handshake"`
	HTTP       bool   `json:"http"`
	TLSVersion uint16 `json:"tls_version,omitempty"`
	Error      string `json:"error,omitempty"`
}

func emit(v any) { _ = json.NewEncoder(os.Stdout).Encode(v) }

func certs(dir string, tamper bool) (tls.Certificate, string, error) {
	now := time.Now()
	rootKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil { return tls.Certificate{}, "", err }
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ML-DSA test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	if err != nil { return tls.Certificate{}, "", err }
	root, err := x509.ParseCertificate(rootDER)
	if err != nil { return tls.Certificate{}, "", err }
	leafKey, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil { return tls.Certificate{}, "", err }
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "a.test"}, DNSNames: []string{"a.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, leafKey.Public(), rootKey)
	if err != nil { return tls.Certificate{}, "", err }
	if tamper {
		leafDER = append([]byte(nil), leafDER...)
		leafDER[len(leafDER)-1] ^= 1 // Last byte is inside Certificate.signatureValue.
	}
	caPath := filepath.Join(dir, "mldsa-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0600); err != nil {
		return tls.Certificate{}, "", err
	}
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}, caPath, nil
}

func origin(args []string) error {
	fs := flag.NewFlagSet("origin", flag.ContinueOnError)
	dir := fs.String("dir", "", "directory for the synthetic CA")
	tamper := fs.Bool("tamper-certificate-signature", false, "corrupt the leaf certificate signature")
	if err := fs.Parse(args); err != nil { return err }
	if *dir == "" { return fmt.Errorf("--dir is required") }
	cert, caPath, err := certs(*dir, *tamper)
	if err != nil { return err }
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { return err }
	defer listener.Close()
	emit(result{Address: listener.Addr().String(), CA: caPath})
	r := result{}
	raw, err := listener.Accept()
	if err != nil { r.Error = err.Error(); emit(r); return nil }
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	conn := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	if err := conn.Handshake(); err != nil { r.Error = err.Error(); emit(r); return nil }
	r.Handshake = true; r.TLSVersion = conn.ConnectionState().Version
	request := make([]byte, 0, 4096); chunk := make([]byte, 1024)
	for !bytes.Contains(request, []byte("\r\n\r\n")) {
		n, err := conn.Read(chunk); request = append(request, chunk[:n]...)
		if err != nil { r.Error = err.Error(); emit(r); return nil }
	}
	if !bytes.Contains(request, []byte("Cookie: sid=from_B")) { r.Error = "B cookie missing"; emit(r); return nil }
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil { r.Error = err.Error(); emit(r); return nil }
	if !bytes.Contains(request, []byte("Host: a.test:"+port+"\r\n")) { r.Error = "rewritten A authority missing"; emit(r); return nil }
	if _, err := conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\na\x00b\xffcde")); err != nil {
		r.Error = err.Error(); emit(r); return nil
	}
	r.HTTP = true; emit(r); return nil
}

func client(args []string) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	address := fs.String("address", "", "bridge address")
	caPath := fs.String("ca", "", "CA bundle")
	if err := fs.Parse(args); err != nil { return err }
	pemBytes, err := os.ReadFile(*caPath)
	if err != nil { return err }
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemBytes) { return fmt.Errorf("CA bundle contains no certificates") }
	conn, err := tls.Dial("tcp", *address, &tls.Config{RootCAs: roots, ServerName: "b.test", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
	if err != nil { return err }
	defer conn.Close()
	_, port, err := net.SplitHostPort(*address)
	if err != nil { return err }
	authority := net.JoinHostPort("b.test", port)
	if _, err := conn.Write([]byte("GET /mldsa HTTP/1.1\r\nHost: "+authority+"\r\nCookie: sid=from_B\r\nConnection: close\r\n\r\n")); err != nil { return err }
	body, err := io.ReadAll(conn)
	if err != nil { return err }
	ok := bytes.Contains(body, []byte("HTTP/1.1 200")) && bytes.Contains(body, []byte("a\x00b\xffcde"))
	emit(result{Handshake: true, HTTP: ok, TLSVersion: conn.ConnectionState().Version})
	if !ok { return fmt.Errorf("unexpected bridged response") }
	return nil
}

func main() {
	if len(os.Args) < 2 { fmt.Fprintln(os.Stderr, "usage: mldsa_probe origin|client"); os.Exit(2) }
	var err error
	switch os.Args[1] { case "origin": err = origin(os.Args[2:]); case "client": err = client(os.Args[2:]); default: err = fmt.Errorf("unknown mode %q", os.Args[1]) }
	if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}
