#!/usr/bin/env python3
"""Independent Go/B interop and malformed-share tests; synthetic loopback only.

This targeted capability lab does not change the default matrix clients or
waive fingerprint differences. Go 1.26+ is required; missing support is an error.
"""
import argparse
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
from types import SimpleNamespace

from lab import certificates, exact, start_bridge

HRR = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


def u16(data):
    return int.from_bytes(data, "big")


def word(number):
    return struct.pack("!H", number)


def inspect_hello(payload, group, mutation=None):
    """Inspect one complete plaintext hello, optionally corrupt its key share."""
    kind = payload[0]
    assert kind in (1, 2) and len(payload) == 4 + int.from_bytes(payload[1:4], "big")
    if kind == 2 and payload[6:38] == HRR:
        assert mutation is None, "negative case unexpectedly used HRR"
        return payload, {"kind": "hrr"}, False
    pos = 38
    pos += 1 + payload[pos]  # legacy session ID
    if kind == 1:
        pos += 2 + u16(payload[pos:pos + 2])
        pos += 1 + payload[pos]
    else:
        pos += 3  # selected cipher + compression
    ext_length_pos = pos
    assert pos + 2 + u16(payload[pos:pos + 2]) == len(payload)
    pos += 2
    shares = []
    changed = False
    while pos < len(payload):
        ext_type, size = struct.unpack("!HH", payload[pos:pos + 4])
        body = payload[pos + 4:pos + 4 + size]
        if ext_type == 51:
            offset = 2 if kind == 1 else 0
            if kind == 1:
                assert u16(body[:2]) == len(body) - 2
            while offset < len(body):
                share_group, length = struct.unpack("!HH", body[offset:offset + 4])
                key = body[offset + 4:offset + 4 + length]
                assert len(key) == length
                shares.append({"group": share_group, "length": length})
                if mutation and share_group == group:
                    assert not changed
                    ec_bytes = 65 if group == 4587 else 97
                    if mutation == "point":
                        key = b"\xff" + key[1:]  # invalid EC point encoding
                    elif mutation == "length":
                        key = key[:-1]
                    elif mutation == "public":
                        assert kind == 1
                        # Two 12-bit coefficients of 4095, outside ML-KEM's q=3329.
                        key = key[:ec_bytes] + b"\xff\xff\xff" + key[ec_bytes + 3:]
                    elif mutation == "ciphertext":
                        assert kind == 2
                        key = key[:ec_bytes] + bytes([key[ec_bytes] ^ 1]) + key[ec_bytes + 1:]
                    else:
                        raise AssertionError("unknown mutation")
                    body = body[:offset + 2] + word(len(key)) + key + body[offset + 4 + length:]
                    if kind == 1:
                        body = word(len(body) - 2) + body[2:]
                    changed = True
                    break
                offset += 4 + length
            if changed:
                payload = payload[:pos + 2] + word(len(body)) + body + payload[pos + 4 + size:]
                payload = (payload[:ext_length_pos] + word(len(payload) - ext_length_pos - 2)
                           + payload[ext_length_pos + 2:])
                payload = payload[:1] + (len(payload) - 4).to_bytes(3, "big") + payload[4:]
                break
        pos += 4 + size
    return payload, {"kind": "client" if kind == 1 else "server", "shares": shares}, changed


class WireProxy:
    def __init__(self, group, output, direction=None, mutation=None):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(12)
        self.port = self.listener.getsockname()[1]
        self.group, self.output = group, output
        self.direction, self.mutation = direction, mutation
        self.changed = False
        self.hellos, self.alerts, self.errors = [], [], []

    def start(self, target):
        self.thread = threading.Thread(target=self.run, args=(target,), daemon=True)
        self.thread.start()

    def run(self, target):
        try:
            left, _ = self.listener.accept()
            right = socket.create_connection(("127.0.0.1", target), timeout=12)
            with left, right:
                left.settimeout(12)
                threads = [threading.Thread(target=self.pump, args=(left, right, "client")),
                           threading.Thread(target=self.pump, args=(right, left, "server"))]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=14)
                    assert not thread.is_alive(), "proxy relay stuck"
        except Exception as exc:
            self.errors.append(repr(exc))
        finally:
            self.listener.close()

    def pump(self, source, target, direction):
        try:
            while True:
                header = exact(source, 5)
                payload = exact(source, u16(header[3:]))
                if header[0] == 22 and payload[0] in (1, 2):
                    index = len(self.hellos)
                    (self.output / f"{index}-{direction}-hello.bin").write_bytes(header + payload)
                    mutation = self.mutation if direction == self.direction and not self.changed else None
                    payload, info, changed = inspect_hello(payload, self.group, mutation)
                    self.hellos.append(info)
                    self.changed |= changed
                    header = header[:3] + word(len(payload))
                elif header[0] == 21 and len(payload) == 2:
                    self.alerts.append({"direction": direction, "description": payload[1]})
                target.sendall(header + payload)
        except (EOFError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:
            self.errors.append(repr(exc))
        finally:
            try:
                target.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def finish(self):
        self.thread.join(timeout=15)
        assert not self.thread.is_alive(), "proxy did not terminate"
        assert not self.errors, self.errors


def run_case(binary, probe, certs, output, group, mode):
    output.mkdir(parents=True)
    direction, mutation = None, None
    if mode.startswith(("server-", "client-")):
        direction, mutation = mode.split("-", 1)
    origin_proxy = WireProxy(group, output, direction if direction == "server" else None, mutation)
    server = subprocess.Popen([str(probe), "-mode", "server", "-group", str(group),
                               "-cert", str(certs / "a.pem"), "-key", str(certs / "a.key"),
                               "-authority", f"a.test:{origin_proxy.port}"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    bridge = log = None
    try:
        server_port = int(server.stdout.readline())
        origin_proxy.start(server_port)
        client_proxy = None
        extra = []
        if direction == "client":
            client_dir = output / "client-wire"
            client_dir.mkdir()
            client_proxy = WireProxy(group, client_dir, direction, mutation)
            extra = ["--public", f"b.test:{client_proxy.port}"]
        elif mode == "wrong-hostname":
            extra = ["--upstream", f"wrong.test:{origin_proxy.port}"]
        bridge, port, log = start_bridge(binary, certs, SimpleNamespace(port=origin_proxy.port),
                                         output / "runtime", extra)
        if client_proxy:
            client_proxy.start(port)
            port = client_proxy.port
        args = [str(probe), "-group", str(group), "-address", f"127.0.0.1:{port}",
                "-ca", str(certs / "ca.pem")]
        if mode == "hrr":
            args.append("-hrr")
        client = subprocess.run(args, capture_output=True, text=True, timeout=15)
        client_result = json.loads(client.stdout)
        server_out, server_err = server.communicate(timeout=15)
        server_result = json.loads(server_out)
        (output / "peers.json").write_text(json.dumps({
            "client": client_result, "client_exit": client.returncode,
            "origin": server_result, "origin_exit": server.returncode,
            "origin_stderr": server_err,
        }, indent=2) + "\n")
        origin_proxy.finish()
        if client_proxy:
            client_proxy.finish()
        positive = mode in ("normal", "hrr")
        if positive:
            assert client.returncode == server.returncode == 0, (client_result, server_result, server_err)
            assert client_result["http"] and server_result["http"]
            assert client_result["tls_version"] == server_result["tls_version"] == 0x0304
            assert server_result["negotiated_group"] == group
            assert client_result["negotiated_group"] == (4588 if mode == "hrr" else group)
            assert sum(h["kind"] == "hrr" for h in origin_proxy.hellos) == (mode == "hrr")
            assert sum(h["kind"] == "client" for h in origin_proxy.hellos) == (2 if mode == "hrr" else 1)
            expected = {4587: (1249, 1153), 4589: (1665, 1665)}[group]
            for kind, size in zip(("client", "server"), expected):
                assert any(h["kind"] == kind and {"group": group, "length": size} in h["shares"]
                           for h in origin_proxy.hellos)
        else:
            assert client.returncode != 0 and server.returncode != 0
            assert not client_result["http"] and not server_result["http"]
            if mutation:
                wire = client_proxy or origin_proxy
                assert wire.changed, "failure without applying the intended mutation"
                if mutation != "ciphertext":
                    expected_direction = "server" if client_proxy else "client"
                    assert {"direction": expected_direction, "description": 47} in wire.alerts, wire.alerts
        result = {"group": group, "case": mode, "pass": True,
                  "client": client_result, "origin": server_result,
                  "origin_hellos": origin_proxy.hellos,
                  "origin_alerts": origin_proxy.alerts,
                  "client_alerts": client_proxy.alerts if client_proxy else []}
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    finally:
        if bridge:
            bridge.terminate()
            bridge.wait(timeout=10)
            log.flush()
            log.seek(0)
            (output / "bridge.log").write_text(log.read())
            log.close()
        if server.poll() is None:
            server.terminate()
            server.wait(timeout=10)
        origin_proxy.listener.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/debug/fingerprint-bridge"))
    parser.add_argument("--probe", type=Path, default=Path("target/matrix-clients/hybrid-probe"))
    parser.add_argument("--output", type=Path, default=Path("test-results/ci-hybrid-lab"))
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="hybrid-lab-") as temporary:
        certs = Path(temporary)
        certificates(certs)
        for group in (4587, 4589):
            for mode in ("normal", "hrr", "server-point", "server-length", "server-ciphertext",
                         "client-point", "client-public", "client-length", "wrong-hostname"):
                results.append(run_case(args.binary.resolve(), args.probe.resolve(), certs,
                                        output / f"{group}-{mode}", group, mode))
                print(f"PASS {group} {mode}", flush=True)
    (output / "summary.json").write_text(json.dumps({"pass": True, "cases": results}, indent=2) + "\n")


if __name__ == "__main__":
    main()
