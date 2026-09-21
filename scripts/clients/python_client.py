"""Python's real http.client + OpenSSL stack; custom dialing keeps DNS local."""
import http.client
import socket
import ssl
import sys

ca, hosts, protocol, a_port, b_port = sys.argv[1:]
assert protocol == "http/1.1"  # stdlib http.client has no HTTP/2 support.
for host, port in [("a.test", a_port), ("a.test", a_port), ("b.test", b_port)]:
    ctx = ssl.create_default_context(cafile=ca)
    ctx.set_alpn_protocols(["http/1.1"])
    conn = http.client.HTTPSConnection(host, int(port), context=ctx, timeout=15)
    conn._create_connection = lambda addr, timeout, source_address=None: socket.create_connection(
        ("127.0.0.1", addr[1]), timeout, source_address)
    base = f"https://{host}:{port}"
    try:
        for n in [1, 2]:
            conn.request("GET", f"/fingerprint/{n}?encoded=%2F", headers={
                "User-Agent": "fp-matrix/python", "Cookie": "sid=from_B; flag=yes",
                "Origin": base, "Referer": base + "/home", "X-Order-Z": "z", "X-Order-A": "a"})
            response = conn.getresponse()
            assert response.status == 200 and response.version == 11
            assert f"Domain={host}" in response.getheader("Set-Cookie")
            assert response.getheader("Location") == base + "/next"
            assert response.read() == b"FP_OK"
    finally:
        conn.close()
print("python http.client:", ssl.OPENSSL_VERSION)
