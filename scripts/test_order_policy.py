"""Positive order allowances and counterexamples against real HPACK bytes."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import hpack

from matrix_config import LAYERS, SAMPLES
from matrix_report import inspect_summary
from order_policy import (HpackOrderProof, equal, http_order_form, order_allowance, origin_http_wire,
                          tls_order_form)
from paired_http import compare
import test_matrix
from test_matrix import matched


def tls(order=0):
    extensions = ([0, 10, 11, 13, 43], [43, 0, 10, 13, 11], [13, 11, 10, 0, 43])[order]
    fields = {"legacy_version": 771, "ciphers": [4865, 4866, 49199],
              "extensions": list(extensions), "other_extensions": [],
              "groups": [29, 23], "point_formats": [0, 1, 2],
              "signature_algorithms": [2052, 1027], "compression": [0],
              "alpn": ["6832"], "sni_present": True}
    ja3 = ",".join(["771", *["-".join(map(str, fields[key]))
                           for key in ("ciphers", "extensions", "groups", "point_formats")]])
    return {"fields": fields, "ja3_string": ja3,
            "ja3": hashlib.md5(ja3.encode()).hexdigest(), "ja4": "unchanged-order-independent-digest"}


def http(authority="a.test:9443", order=0, huffman=True, value="1", never=False, duplicates=False, second_order=None):
    encoder, requests = hpack.Encoder(), []
    for n, stream in enumerate((1, 3), 1):
        ordinary = [("cookie", "sid=from_B; flag=yes"), ("x-one", value), ("x-two", "2")]
        if duplicates:
            ordinary = [("x-duplicate", "first"), ("x-duplicate", "second")]
        current_order = order if n == 1 or second_order is None else second_order
        if current_order == 1:
            ordinary.reverse()
        elif current_order == 2:
            ordinary = ordinary[1:] + ordinary[:1]
        headers = [(":method", "GET"), (":scheme", "https"), (":authority", authority),
                   (":path", f"/fingerprint/{n}"), *ordinary]
        encoded = [hpack.NeverIndexedHeaderTuple(*pair) for pair in headers] if never else headers
        block = encoder.encode(encoded, huffman=huffman)
        requests.append({"stream": stream, "headers": [list(pair) for pair in headers],
                         "hpack_sha256": hashlib.sha256(block).hexdigest(), "hpack_block": block.hex(),
                         "header_frames": [{"type": 1, "flags": 5, "length": len(block), "prefix": "", "padding": ""}]})
    return {"protocol": "h2", "controls": [{"type": 4, "flags": 0, "stream": 0, "payload": ""}], "requests": requests}


def write(path, data):
    path.write_text(json.dumps(data))


def fixture(directory, tls_order=True, http_order=True):
    directory.mkdir(parents=True, exist_ok=True)
    runtime = directory / "runtime"
    runtime.mkdir(exist_ok=True)
    samples = []
    for n, name in enumerate(SAMPLES):
        sample = {"tls": tls(n if tls_order else 0), "http": http(order=n if http_order else 0),
                  "tcp": {"window": 65535, "options": [[2, 1460], [4], [1], [3, 7]]}}
        samples.append(sample)
        write(directory / f"{name}.json", sample)
    mapping = {"public": "b.test:8443", "upstream": "a.test:9443"}
    pair = {"protocol": "h2", "inbound": {"truncated": False,
            "bytes": list(origin_http_wire(http(mapping["public"], 2 if http_order else 0)))},
            "outbound": {"truncated": False, "bytes": list(origin_http_wire(samples[2]["http"]))}}
    write(runtime / "connection.http.json", pair)
    write(runtime / "connection.report.json", {"comparison": matched()})
    for side in ("inbound", "outbound"):
        write(runtime / f"connection.{side}.json", {"tls": samples[2]["tls"]})
    def comparisons(left, right):
        return {layer: matched() if equal(left[layer], right[layer]) else {
            "pass": False, "missing_layers": [], "differences": [
                {"field": f"/{layer}", "baseline": left[layer], "observed": right[layer]}]}
                for layer in LAYERS}
    return {"client": "go", "protocol": "h2", "raw_status": "inconclusive-baseline",
            "status": "inconclusive-baseline", "baseline": comparisons(samples[0], samples[1]),
            "layers": comparisons(samples[0], samples[2]), "tls_limitations": [], "mapping": mapping,
            "paired_tls": matched(), "paired_http": compare(pair, **mapping)}


class OrderPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name)
        self.result = fixture(self.path)

    def tearDown(self):
        self.temporary.cleanup()

    def change(self, sample, transform):
        path = self.path / f"{sample}.json"
        document = json.loads(path.read_text())
        transform(document)
        write(path, document)

    def rejected(self):
        self.assertFalse(order_allowance(self.result, self.path)["accepted"])

    def test_real_hpack_permutations_and_dynamic_indices_are_proven(self):
        left, right = http(order=0), http(order=1, second_order=0)
        self.assertNotEqual(left["requests"][1]["hpack_block"], right["requests"][1]["hpack_block"])
        self.assertEqual(http_order_form(left), http_order_form(right))
        self.assertEqual(order_allowance(self.result, self.path)["layers"], ["tls", "http"])

    def test_tls_only_allowance_does_not_mutate_original_evidence(self):
        result = fixture(self.path, http_order=False)
        before = (self.path / "direct-1.json").read_bytes()
        self.assertTrue(order_allowance(result, self.path)["accepted"])
        self.assertEqual(order_allowance(result, self.path)["layers"], ["tls"])
        self.assertEqual((self.path / "direct-1.json").read_bytes(), before)

    def test_http_only_allowance(self):
        result = fixture(self.path, tls_order=False)
        self.assertEqual(order_allowance(result, self.path)["layers"], ["http"])

    def test_stable_sample_coincidence_still_requires_proven_order_only(self):
        # Two direct samples can choose the same order by chance. The third
        # independent request may differ, while B must preserve that request.
        (self.path / "direct-2.json").write_bytes((self.path / "direct-1.json").read_bytes())
        self.assertTrue(order_allowance(self.result, self.path)["accepted"])

    def test_tls_payload_cipher_and_group_changes_not_allowed(self):
        for field, value in [("other_extensions", [[1234, "changed"]]),
                             ("ciphers", [4866, 4865, 49199]), ("groups", [23, 29]),
                             ("signature_algorithms", [1027, 2052])]:
            with self.subTest(field=field):
                self.result = fixture(self.path)
                self.change("direct-2", lambda d: d["tls"]["fields"].update({field: value}))
                self.rejected()

    def test_tls_extension_multiplicity_and_bad_ja3_not_allowed(self):
        self.change("direct-2", lambda d: d["tls"].update(ja3="0" * 32))
        self.rejected()
        changed = tls(1)
        changed["fields"]["extensions"].append(0)
        pieces = changed["ja3_string"].split(",")
        pieces[2] += "-0"
        changed["ja3_string"] = ",".join(pieces)
        changed["ja3"] = hashlib.md5(changed["ja3_string"].encode()).hexdigest()
        self.assertNotEqual(tls_order_form(tls(1)), tls_order_form(changed))

    def test_dynamic_reference_width_changes_are_proven(self):
        ordinary = [(f"x-{i:03}", "value") for i in range(90)]
        samples = []
        for headers in (ordinary, list(reversed(ordinary))):
            encoder, document = hpack.Encoder(), http()
            for request, fields in zip(document["requests"], (headers, [ordinary[0]])):
                block = encoder.encode(fields)
                request.update(headers=[list(pair) for pair in fields], hpack_block=block.hex(),
                               hpack_sha256=hashlib.sha256(block).hexdigest())
                request["header_frames"][0]["length"] = len(block)
            samples.append(document)
        self.assertNotEqual(len(samples[0]["requests"][1]["hpack_block"]),
                            len(samples[1]["requests"][1]["hpack_block"]))
        self.assertEqual(http_order_form(samples[0]), http_order_form(samples[1]))

    def test_nonminimal_hpack_integer_and_late_table_update_are_rejected(self):
        with self.assertRaisesRegex(AssertionError, "nonminimal HPACK integer"):
            HpackOrderProof().block(b"\x00\x01x\x7f\x83\x00" + b"a" * 130, [("x", "a" * 130)])
        with self.assertRaises(hpack.HPACKError):
            HpackOrderProof().block(b"\x40\x01x\x01a\x20", [("x", "a")])

    def test_tls_allowance_with_http1_still_preserves_http1_order(self):
        result = fixture(self.path, http_order=False)
        def h1(authority):
            return {"protocol": "http/1.1", "requests": [{"head":
                f"GET /{n} HTTP/1.1\r\nHost: {authority}\r\nCookie: sid=from_B\r\n\r\n"}
                for n in (1, 2)]}
        for sample in SAMPLES:
            self.change(sample, lambda d: d.update(http=h1(result["mapping"]["upstream"])))
        pair = {"protocol": "http/1.1", **{side: {"truncated": False,
            "bytes": list(origin_http_wire(h1(result["mapping"][authority])))}
            for side, authority in (("inbound", "public"), ("outbound", "upstream"))}}
        write(self.path / "runtime/connection.http.json", pair)
        result["paired_http"] = compare(pair, **result["mapping"])
        self.assertTrue(order_allowance(result, self.path)["accepted"])
        self.change("direct-2", lambda d: d["http"]["requests"].reverse())
        self.assertFalse(order_allowance(result, self.path)["accepted"])

    def test_hpack_huffman_and_indexing_choices_not_allowed(self):
        for changed in (http(order=1, huffman=False), http(order=1, never=True)):
            self.assertNotEqual(http_order_form(http()), http_order_form(changed))
            self.change("direct-2", lambda d: d.update(http=changed))
            self.rejected()

    def test_encoded_value_and_duplicate_header_order_not_allowed(self):
        changed = http(order=1, value="different")
        self.change("direct-2", lambda d: d.update(http=changed))
        self.rejected()
        self.assertNotEqual(http_order_form(http(duplicates=True)),
                            http_order_form(http(duplicates=True, order=1)))

    def test_request_order_stream_settings_and_frame_flags_not_allowed(self):
        transforms = [lambda d: d["http"]["requests"].reverse(),
                      lambda d: d["http"]["requests"][0].update(stream=5),
                      lambda d: d["http"]["controls"][0].update(payload="000100001000"),
                      lambda d: d["http"]["requests"][0]["header_frames"][0].update(flags=4)]
        for transform in transforms:
            self.result = fixture(self.path)
            self.change("direct-2", transform)
            self.rejected()

    def test_missing_raw_block_or_wrong_digest_not_allowed(self):
        self.change("direct-2", lambda d: d["http"]["requests"][0].pop("hpack_block"))
        self.rejected()
        self.result = fixture(self.path)
        self.change("direct-2", lambda d: d["http"]["requests"][0].update(hpack_sha256="0" * 64))
        self.rejected()

    def test_tcp_variance_and_missing_layer_not_allowed(self):
        self.change("direct-2", lambda d: d["tcp"].update(window=123))
        self.rejected()
        self.result = fixture(self.path)
        self.change("direct-2", lambda d: d.update(tcp=None))
        self.rejected()

    def test_b_tls_reordering_is_not_allowed_even_with_forged_pass(self):
        write(self.path / "runtime/connection.outbound.json", {"tls": tls(0)})
        self.rejected()

    def test_b_http_reordering_is_not_allowed_even_with_forged_pass(self):
        path = self.path / "runtime/connection.http.json"
        pair = json.loads(path.read_text())
        pair["outbound"]["bytes"] = list(origin_http_wire(http(order=0)))
        write(path, pair)
        self.rejected()

    def test_a_capture_must_correspond_to_b_output(self):
        self.change("bridged", lambda d: d.update(http=http(order=0)))
        self.rejected()
        self.result = fixture(self.path)
        self.change("bridged", lambda d: d.update(tls=tls(0)))
        self.rejected()

    def test_truncated_paired_evidence_and_report_mismatch_fail(self):
        path = self.path / "runtime/connection.http.json"
        pair = json.loads(path.read_text())
        pair["inbound"]["truncated"] = True
        write(path, pair)
        self.rejected()
        self.result = fixture(self.path)
        write(self.path / "runtime/connection.report.json", {"comparison": {"pass": True}})
        self.rejected()

    def test_paired_false_or_contradictory_summary_never_allowed(self):
        self.result["paired_http"]["pass"] = False
        self.rejected()
        self.result = fixture(self.path)
        self.result["paired_tls"]["differences"] = ["deliberate"]
        self.rejected()

    def test_aggregate_rechecks_waiver_and_dropped_pcap_still_fails(self):
        directory, document = test_matrix.CoverageTests().fixture(self.path)
        index = next(i for i, r in enumerate(document["results"]) if (r["client"], r["protocol"]) == ("go", "h2"))
        case = directory / "go-h2"
        result = fixture(case)
        result["order_allowance"] = order_allowance(result, case)
        self.assertTrue(result["order_allowance"]["accepted"])
        result["status"] = "match-order-variance"
        document["results"][index] = result
        _, rows = inspect_summary(document, directory)
        self.assertEqual(rows[index]["status"], "match-order-variance")
        # A forged summary cannot hide a different real outgoing order.
        write(case / "runtime/connection.outbound.json", {"tls": tls(0)})
        with self.assertRaisesRegex(AssertionError, "unverified order allowance"):
            inspect_summary(document, directory)
        (case / "bridged.pcap").unlink()
        _, rows = inspect_summary(document, directory)
        self.assertEqual(rows[index]["status"], "missing-evidence")


if __name__ == "__main__":
    unittest.main()
