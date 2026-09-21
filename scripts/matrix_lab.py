#!/usr/bin/env python3
"""A-side wire evidence for independent native language clients.

0 = all requested fingerprints match; 1 = differences/missing/unstable baseline;
2 = infrastructure, client, protocol or capture error. --report-only relaxes 1,
never 2, and does not change any recorded fingerprint verdict.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import traceback

import h2.config
import h2.connection
import h2.events

from lab import PREFACE, SynCapture, certificates, exact, frame, head, hello_peek, read_frame, start_bridge
from matrix_config import CASES, LAYERS, SAMPLES

ROOT = Path(__file__).resolve().parent.parent


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def response_headers(port):
    return [(":status", "200"), ("content-length", "5"),
            ("set-cookie", "sid=from_A; Domain=a.test; Path=/; Secure; HttpOnly; SameSite=Lax"),
            ("location", f"https://a.test:{port}/next")]


def validate_requests(http, port):
    requests = http["requests"]
    if len(requests) != 2:
        raise AssertionError("two requests must reuse one connection")
    for n, request in enumerate(requests, 1):
        if http["protocol"] == "http/1.1":
            lines = request["head"].split("\r\n")
            assert lines[0] == f"GET /fingerprint/{n}?encoded=%2F HTTP/1.1"
            headers = [(k.lower(), v.strip()) for k, v in (line.split(":", 1) for line in lines[1:] if line)]
            authority = "host"
        else:
            headers = request["headers"]
            assert (":method", "GET") in headers
            assert (":path", f"/fingerprint/{n}?encoded=%2F") in headers
            authority = ":authority"
        for item in [(authority, f"a.test:{port}"), ("cookie", "sid=from_B; flag=yes"),
                     ("origin", f"https://a.test:{port}"), ("referer", f"https://a.test:{port}/home")]:
            assert item in headers, f"missing or incorrectly rewritten {item[0]}"


class MatrixOrigin:
    def __init__(self, path, protocol):
        self.protocol = protocol
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(path / "a.pem", path / "a.key")
        self.ctx.set_alpn_protocols([protocol])
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(30)
        self.port = self.listener.getsockname()[1]
        self.evidence, self.errors, self.workers = {}, [], []
        self.closed = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            for sample in SAMPLES:
                raw, peer = self.listener.accept()
                worker = threading.Thread(target=self.handle, args=(sample, raw, peer), daemon=True)
                self.workers.append(worker)
                worker.start()
        except (OSError, TimeoutError):
            if not self.closed.is_set():
                self.errors.append(traceback.format_exc())

    def handle(self, sample, raw, peer):
        entry = {"source_port": peer[1]}
        self.evidence[sample] = entry
        try:
            raw.settimeout(15)
            entry["hello"] = hello_peek(raw)
            with self.ctx.wrap_socket(raw, server_side=True) as conn:
                negotiated = conn.selected_alpn_protocol()
                # HTTP/1.1 clients may legitimately omit ALPN (e.g. JDK HTTP_1_1).
                assert negotiated == self.protocol or (self.protocol == "http/1.1" and negotiated is None), "ALPN downgrade"
                entry["http"] = self.h2(conn) if self.protocol == "h2" else self.h1(conn)
                validate_requests(entry["http"], self.port)
                # Drain late ACKs; don't turn unread incoming bytes into a TCP RST.
                conn.settimeout(.5)
                try:
                    while conn.recv(65536):
                        pass
                except (TimeoutError, OSError):
                    pass
        except Exception:
            entry["error"] = traceback.format_exc()
            self.errors.append(entry["error"])
        finally:
            raw.close()

    def h1(self, conn):
        requests = []
        for _ in range(2):
            incoming = head(conn)
            requests.append({"head": incoming.decode("ascii"), "body_sha256": hashlib.sha256(b"").hexdigest()})
            outgoing = "HTTP/1.1 200 OK\r\n" + "".join(f"{k}: {v}\r\n" for k, v in response_headers(self.port)[1:])
            conn.sendall(outgoing.encode() + b"\r\nFP_OK")
        return {"protocol": "http/1.1", "requests": requests}

    def h2(self, conn):
        server = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False, header_encoding="utf-8"))
        server.initiate_connection()
        conn.sendall(server.data_to_send())
        preface = exact(conn, len(PREFACE))
        assert preface == PREFACE
        server.receive_data(preface)
        controls, requests, blocks, layouts = [], [], {}, {}
        done = set()
        while len(done) < 2:
            kind, flags, stream, data = read_frame(conn)
            if kind in (4, 2, 8) and not (kind == 4 and flags & 1):
                controls.append({"type": kind, "flags": flags, "stream": stream, "payload": data.hex()})
            if kind in (1, 9):
                layouts.setdefault(stream, []).append({"type": kind, "flags": flags, "length": len(data)})
                if kind == 1:
                    padding = data[0] if flags & 8 else 0
                    prefix = (1 if flags & 8 else 0) + (5 if flags & 32 else 0)
                    layouts[stream][-1]["prefix"] = data[:prefix].hex()
                    layouts[stream][-1]["padding"] = data[-padding:].hex() if padding else ""
                    block = data[prefix:len(data)-padding if padding else None]
                else:
                    block = data
                blocks.setdefault(stream, bytearray()).extend(block)
            for event in server.receive_data(frame(kind, flags, stream, data)):
                if isinstance(event, h2.events.RequestReceived):
                    requests.append({"stream": event.stream_id, "headers": event.headers,
                                     "hpack_sha256": hashlib.sha256(blocks[event.stream_id]).hexdigest(),
                                     "header_frames": layouts[event.stream_id]})
                elif isinstance(event, h2.events.DataReceived):
                    raise AssertionError("unexpected GET request body")
                elif isinstance(event, h2.events.StreamEnded):
                    done.add(event.stream_id)
                    server.send_headers(event.stream_id, response_headers(self.port))
                    server.send_data(event.stream_id, b"FP_OK", end_stream=True)
                elif isinstance(event, (h2.events.ConnectionTerminated, h2.events.StreamReset)):
                    raise AssertionError("client terminated before responses")
            outgoing = server.data_to_send()
            if outgoing:
                conn.sendall(outgoing)
        return {"protocol": "h2", "controls": controls, "requests": requests}

    def finish(self):
        self.thread.join(timeout=5)
        for worker in self.workers:
            worker.join(timeout=16)
        assert not self.thread.is_alive() and all(not w.is_alive() for w in self.workers), "origin threads timed out"
        assert set(self.evidence) == set(SAMPLES), "missing connection or unexpected connection reuse"
        assert not self.errors, self.errors

    def close(self):
        self.closed.set()
        self.listener.close()


def compare(binary, left, right, layers):
    result = subprocess.run([str(binary), "compare", str(left), str(right), "--layers", ",".join(layers)], capture_output=True, text=True, timeout=10)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr or result.stdout)
    doc = json.loads(result.stdout)
    assert doc["pass"] == (result.returncode == 0)
    return doc


def client_command(client, path, protocol, a_port, b_port):
    hosts = path / "hosts"
    hosts.write_text("127.0.0.1 localhost a.test b.test\n")
    commands = {
        "python": [sys.executable, str(ROOT / "scripts/clients/python_client.py")],
        "node": ["node", str(ROOT / "scripts/clients/node_client.mjs")],
        "go": [str(ROOT / "target/matrix-clients/go-client")],
        "java": ["java", f"-Djdk.net.hosts.file={hosts}", "-cp", str(ROOT / "target/matrix-clients"), "JavaClient"],
        "rust": [str(ROOT / "target/debug/examples/language-client")],
    }
    return commands[client] + [str(path / "ca.pem"), str(hosts), protocol, str(a_port), str(b_port)]


def classify(baseline, layers):
    if any(layer["missing_layers"] for layer in [*baseline.values(), *layers.values()]):
        return "missing-evidence"
    if not all(layer["pass"] for layer in baseline.values()):
        return "inconclusive-baseline"
    return "match" if all(layer["pass"] for layer in layers.values()) else "mismatch"


def run_case(binary, path, output, client, protocol, interface):
    output.mkdir(parents=True, exist_ok=True)
    result = {"client": client, "protocol": protocol, "status": "error", "baseline": {}, "layers": {}}
    origin = MatrixOrigin(path, protocol)
    proc = log = capture = None
    try:
        capture = SynCapture(interface, origin.port) if interface else None
        proc, port, log = start_bridge(binary, path, origin, output / "runtime")
        completed = subprocess.run(client_command(client, path, protocol, origin.port, port),
                                   capture_output=True, text=True, timeout=65)
        (output / "client.log").write_text(completed.stdout + completed.stderr)
        if completed.returncode:
            raise RuntimeError(f"{client} exited {completed.returncode}: {completed.stderr[-4000:]}")
        origin.finish()
    except Exception:
        result["error"] = traceback.format_exc()
    finally:
        # Save all usable evidence even after a client/handshake failure.
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait(timeout=5)
        if log:
            log.flush(); log.seek(0)
            (output / "bridge.log").write_text(log.read())
            log.close()
        origin.close()
        try:
            for sample in SAMPLES:
                entry = origin.evidence.get(sample, {})
                document = {"tls": None, "http": entry.get("http"), "tcp": None}
                if "hello" in entry:
                    wire = output / f"{sample}.clienthello.bin"
                    wire.write_bytes(entry["hello"])
                    document.update(json.loads(subprocess.check_output([str(binary), "inspect-hello", str(wire)], text=True, timeout=10)))
                if capture and "source_port" in entry:
                    pcap = output / f"{sample}.pcap"
                    pcap.write_bytes(capture.pcap(entry["source_port"]))
                    document.update(json.loads(subprocess.check_output([str(binary), "inspect-pcap", str(pcap)], text=True, timeout=10)))
                write_json(output / f"{sample}.json", document)
            for layer in LAYERS:
                result["baseline"][layer] = compare(binary, output / "direct-1.json", output / "direct-2.json", [layer])
                result["layers"][layer] = compare(binary, output / "direct-1.json", output / "bridged.json", [layer])
            if "error" not in result:
                result["status"] = classify(result["baseline"], result["layers"])
        except Exception:
            result["evidence_error"] = traceback.format_exc()
            result["status"] = "error"
        finally:
            if capture:
                capture.close()
        write_json(output / "result.json", result)
    return result


def environment():
    versions = {}
    for name, command in {"rust": ["rustc", "--version"], "node": ["node", "--version"],
                          "go": ["go", "version"], "java": ["java", "-version"],
                          "openssl": ["openssl", "version"], "libc": ["ldd", "--version"]}.items():
        try:
            p = subprocess.run(command, capture_output=True, text=True, timeout=10)
            versions[name] = (p.stdout + p.stderr).strip()
        except (OSError, subprocess.TimeoutExpired) as error:
            versions[name] = str(error)
    return {"architecture": platform.machine(), "kernel": platform.release(),
            "distribution": Path("/etc/os-release").read_text(), "python": sys.version,
            "python_tls": ssl.OPENSSL_VERSION, "versions": versions,
            "matrix_arch": os.environ.get("MATRIX_ARCH", "local"),
            "matrix_distro": os.environ.get("MATRIX_DISTRO", "local"),
            "image_id": os.environ.get("MATRIX_IMAGE_ID", "local"),
            "scope": "native architecture, distro container userland; TCP kernel is shared with the runner; loopback only"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/debug/fingerprint-bridge")
    parser.add_argument("--output", type=Path, default=ROOT / "test-results/ci-matrix-local")
    parser.add_argument("--clients", default="python,node,go,java,rust")
    parser.add_argument("--capture-interface", default="lo")
    parser.add_argument("--no-capture", action="store_true", help="local diagnosis only: TCP remains missing and cannot pass")
    parser.add_argument("--report-only", action="store_true", help="emit mismatches without exit 1; errors still exit 2")
    args = parser.parse_args()
    selected = args.clients.split(",")
    assert selected and len(set(selected)) == len(selected) and set(selected) <= {c for c, _ in CASES}
    args.output.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="fp-matrix-") as temporary:
        path = Path(temporary)
        certificates(path)
        for client, protocol in CASES:
            if client in selected:
                result = run_case(args.binary.resolve(), path, args.output / f"{client}-{protocol.replace('/', '-')}",
                                  client, protocol, None if args.no_capture else args.capture_interface)
                results.append(result)
                print(f"{client:6} {protocol:8} {result['status']}", flush=True)
    summary = {"schema_version": 1, "environment": environment(), "results": results,
               "fingerprint_pass": bool(results) and all(r["status"] == "match" for r in results),
               "report_only": args.report_only, "tcp_capture_requested": not args.no_capture}
    write_json(args.output / "matrix-summary.json", summary)
    if any(r["status"] == "error" for r in results):
        return 2
    return 0 if summary["fingerprint_pass"] or args.report_only else 1


if __name__ == "__main__":
    sys.exit(main())
