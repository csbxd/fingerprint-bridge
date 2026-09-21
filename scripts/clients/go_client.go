// Go net/http + crypto/tls, with a local dialer and normal certificate verification.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

func main() {
	ca, err := os.ReadFile(os.Args[1])
	must(err)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		panic("invalid CA")
	}
	protocol := os.Args[3]
	for _, target := range [][2]string{{"a.test", os.Args[4]}, {"a.test", os.Args[4]}, {"b.test", os.Args[5]}} {
		host, port := target[0], target[1]
		transport := &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool}, ForceAttemptHTTP2: protocol == "h2",
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp4", "127.0.0.1:"+port)
			},
		}
		if protocol != "h2" {
			transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
		}
		client := &http.Client{Transport: transport, Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
		base := "https://" + host + ":" + port
		for _, n := range []int{1, 2} {
			req, err := http.NewRequest("GET", fmt.Sprintf("%s/fingerprint/%d?encoded=%%2F", base, n), nil)
			must(err)
			for key, value := range map[string]string{"User-Agent": "fp-matrix/go", "Cookie": "sid=from_B; flag=yes", "Origin": base, "Referer": base + "/home", "X-Order-Z": "z", "X-Order-A": "a"} {
				req.Header.Set(key, value)
			}
			response, err := client.Do(req)
			must(err)
			body, err := io.ReadAll(response.Body)
			must(err)
			response.Body.Close()
			want := 1
			if protocol == "h2" {
				want = 2
			}
			if response.StatusCode != 200 || response.ProtoMajor != want || string(body) != "FP_OK" || !strings.Contains(response.Header.Get("Set-Cookie"), "Domain="+host) || response.Header.Get("Location") != base+"/next" {
				panic("response validation failed")
			}
		}
		transport.CloseIdleConnections()
	}
	fmt.Println(runtime.Version(), "net/http crypto/tls")
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
