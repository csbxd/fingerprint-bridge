"""Regression tests for the evidence gate, not just workflow YAML shape."""
import copy
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest

from lab import certificates, hello_peek
from matrix_config import ARCHITECTURES, CASES, DISTRIBUTIONS, LAYERS, SAMPLES
from matrix_lab import classify
from matrix_report import collect, inspect_summary, layer_status


def matched():
    return {"pass": True, "differences": [], "missing_layers": []}


def comparisons():
    return {layer: matched() for layer in LAYERS}


class VerdictTests(unittest.TestCase):
    def test_induced_differences_each_layer_fail(self):
        for layer in LAYERS:
            observed = comparisons()
            observed[layer] = {"pass": False, "missing_layers": [],
                               "differences": [{"field": f"/{layer}/deliberate", "expected": 1, "observed": 2}]}
            self.assertEqual(classify(comparisons(), observed), "mismatch")

    def test_unstable_direct_baseline_never_silently_normalized(self):
        baseline = comparisons()
        baseline["tls"]["pass"] = False
        baseline["tls"]["differences"] = [{"field": "/tls/extensions"}]
        self.assertEqual(classify(baseline, comparisons()), "inconclusive-baseline")

    def test_missing_tcp_never_matches(self):
        observed = comparisons()
        observed["tcp"] = {"pass": False, "differences": [], "missing_layers": ["tcp"]}
        self.assertEqual(classify(comparisons(), observed), "missing-evidence")
        self.assertEqual(layer_status(observed["tcp"]), "MISSING")

    def test_contradictory_boolean_not_a_match(self):
        self.assertEqual(layer_status({"pass": True, "differences": ["changed"], "missing_layers": []}), "DIFF")


class CoverageTests(unittest.TestCase):
    def fixture(self, root, arch="amd64", distro="ubuntu-24.04"):
        directory = root / f"{arch}-{distro}"
        directory.mkdir()
        results = []
        for client, protocol in CASES:
            case_dir = directory / f"{client}-{protocol.replace('/', '-')}"
            case_dir.mkdir()
            (case_dir / "runtime").mkdir()
            for suffix in ("http.json", "report.json"):
                (case_dir / "runtime" / f"connection.{suffix}").write_text("test evidence")
            for sample in SAMPLES:
                for suffix in ("json", "clienthello.bin", "pcap"):
                    (case_dir / f"{sample}.{suffix}").write_bytes(b"test evidence")
            results.append({"client": client, "protocol": protocol, "status": "match",
                            "baseline": comparisons(), "layers": comparisons(), "paired_tls": matched(),
                            "paired_http": {"pass": True, "inbound": {}, "outbound": {}}})
        document = {"environment": {"matrix_arch": arch, "matrix_distro": distro,
                    "architecture": {"amd64": "x86_64", "arm64": "aarch64"}[arch]},
                    "tcp_capture_requested": True, "results": results}
        (directory / "matrix-summary.json").write_text(json.dumps(document))
        return directory, document

    def test_all_72_cells_required(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for arch in ARCHITECTURES:
                for distro in DISTRIBUTIONS:
                    self.fixture(root, arch, distro)
            rows, errors = collect(root)
            self.assertFalse(errors)
            self.assertEqual(len(rows), 72)
            self.assertTrue(all(r["status"] == "match" for r in rows))

    def test_missing_environment_keeps_nine_failed_cells(self):
        with tempfile.TemporaryDirectory() as temp:
            self.fixture(Path(temp))
            rows, errors = collect(Path(temp))
            self.assertEqual(len(rows), 72)
            self.assertEqual(len(errors), 7)
            self.assertEqual(sum(r["status"] == "missing-evidence" for r in rows), 63)

    def test_lost_pcap_invalidates_match(self):
        with tempfile.TemporaryDirectory() as temp:
            directory, document = self.fixture(Path(temp))
            (directory / "python-http-1.1/bridged.pcap").unlink()
            _, rows = inspect_summary(document, directory)
            self.assertEqual(rows[0]["status"], "missing-evidence")

    def test_duplicate_case_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory, document = self.fixture(Path(temp))
            document["results"][-1] = copy.deepcopy(document["results"][0])
            with self.assertRaisesRegex(AssertionError, "cases"):
                inspect_summary(document, directory)

    def test_wrong_native_arch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            directory, document = self.fixture(Path(temp))
            document["environment"]["architecture"] = "aarch64"
            with self.assertRaisesRegex(AssertionError, "architecture"):
                inspect_summary(document, directory)


class CertificateTests(unittest.TestCase):
    def test_lab_certificates_pass_strict_server_auth(self):
        # Python 3.13+ enables X509_STRICT by default. Keep validation enabled.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            certificates(root)
            for name in ("a", "b"):
                checked = subprocess.run(["openssl", "verify", "-x509_strict", "-purpose", "sslserver",
                    "-verify_hostname", f"{name}.test", "-CAfile", str(root / "ca.pem"),
                    str(root / f"{name}.pem")], capture_output=True, text=True)
                self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)


class HelloCaptureTests(unittest.TestCase):
    def test_fragmented_records_are_peeked_without_consuming(self):
        left, right = socket.socketpair()
        hello = b"\x01\x00\x00\x06abcdef"
        wire = b"\x16\x03\x01\x00\x03" + hello[:3] + b"\x16\x03\x01\x00\x07" + hello[3:]
        def send():
            right.sendall(wire[:8])
            time.sleep(.02)
            right.sendall(wire[8:])
        thread = threading.Thread(target=send)
        try:
            thread.start()
            self.assertEqual(hello_peek(left), wire)
            self.assertEqual(left.recv(len(wire)), wire)
        finally:
            thread.join(); left.close(); right.close()


if __name__ == "__main__":
    unittest.main()
