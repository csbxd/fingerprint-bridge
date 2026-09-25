"""Explicit independent-connection order allowance; B-paired checks stay strict.

Never alter the Rust comparison or raw evidence. Prove equality after only TLS
extension permutation or HTTP/2 header permutation, including its HPACK dynamic
reference consequences. Requests, values, duplicate-header order, representation
choices, settings, frame flags and TCP remain significant.
"""
from collections import Counter
import copy
import hashlib
import json

import hpack

from paired_http import compare as compare_paired_http, normalize as paired_http_form
from lab import PREFACE, frame

POLICY = "independent-order-v1"
ACCEPTED = ("match", "match-order-variance")


def equal(left, right):
    return json.dumps(left, sort_keys=True, separators=(",", ":")) == json.dumps(right, sort_keys=True, separators=(",", ":"))


def strict_match(comparison):
    return (isinstance(comparison, dict) and comparison.get("pass") is True and
            comparison.get("differences") == [] and comparison.get("missing_layers") == [])


def paired_match(result):
    http = result.get("paired_http", {})
    return (strict_match(result.get("paired_tls")) and http.get("pass") is True and
            "inbound" in http and "outbound" in http and equal(http["inbound"], http["outbound"]))


def tls_order_form(tls):
    output = copy.deepcopy(tls)
    fields = output["fields"]

    def ja3():
        def vector(values):
            return "-".join(str(n) for n in values
                            if not (n & 0x0f0f == 0x0a0a and n >> 8 == n & 255))
        return ",".join([str(fields["legacy_version"]), *(
            vector(fields[key]) for key in ("ciphers", "extensions", "groups", "point_formats"))])

    original = ja3()
    assert output["ja3_string"] == original, "JA3 string does not describe captured fields"
    assert output["ja3"] == hashlib.md5(original.encode()).hexdigest(), "incorrect JA3 digest"
    fields["extensions"].sort()
    fields["other_extensions"].sort(key=lambda value: json.dumps(value, sort_keys=True))
    output["ja3_string"] = ja3()
    output["ja3"] = hashlib.md5(output["ja3_string"].encode()).hexdigest()
    return output


def integer(data, position, bits):
    start, mask = position, (1 << bits) - 1
    value = data[position] & mask
    high = data[position] & ~mask
    position += 1
    if value == mask:
        shift = 0
        while True:
            byte = data[position]
            position += 1
            value += (byte & 127) << shift
            if not byte & 128:
                break
            shift += 7
            assert shift <= 56, "oversized HPACK integer"
    encoded = bytearray([high | min(value, mask)])
    if value >= mask:
        remaining = value - mask
        while remaining >= 128:
            encoded.append((remaining & 127) | 128)
            remaining >>= 7
        encoded.append(remaining)
    assert data[start:position] == encoded, "nonminimal HPACK integer is not order variance"
    return value, position


def string(data, position):
    start = position
    size, position = integer(data, position, 7)
    end = position + size
    assert end <= len(data), "truncated HPACK string"
    # Retain the Huffman flag, length and exact literal bytes.
    return data[start:end].hex(), end


class HpackOrderProof:
    def __init__(self):
        self.decoder = hpack.Decoder()
        self.validator = hpack.Decoder()
        self.tags = []
        self.generations = Counter()

    def block(self, block, headers):
        assert block and len(block) <= 1 << 20, "missing or oversized HPACK block"
        # Whole-block validation enforces table updates only at the start.
        decoded = self.validator.decode(block, raw=True)
        expected = [(name.encode(), value.encode()) for name, value in headers]
        assert decoded == expected, "HPACK bytes do not encode the captured headers"
        fields, updates, position = [], [], 0
        while position < len(block):
            start, byte = position, block[position]
            bits = 7 if byte & 128 else 6 if byte & 64 else 5 if byte & 32 else 4
            index, position = integer(block, position, bits)
            kind = "indexed" if bits == 7 else "incremental" if bits == 6 else "table-size" if bits == 5 else "never" if byte & 16 else "without"
            token = {"kind": kind}
            if kind != "table-size":
                # A dynamic reference is identified by its real insertion,
                # not just header text. Identical repeated entries stay distinct.
                token["reference"] = self.tags[index - 62] if index > 61 else index
            if kind not in ("indexed", "table-size"):
                if index == 0:
                    token["name_wire"], position = string(block, position)
                token["value_wire"], position = string(block, position)
            part = self.decoder.decode(block[start:position], raw=True)
            if kind == "table-size":
                assert not fields, "late HPACK table-size update"
                updates.append(index)
            else:
                assert len(part) == 1
                name, value = part[0]
                token.update(name=name.hex(), value=value.hex())
                fields.append(token)
                if kind == "incremental":
                    identity = (name.hex(), value.hex())
                    self.generations[identity] += 1
                    self.tags.insert(0, [*identity, self.generations[identity]])
            self.tags = self.tags[:len(self.decoder.header_table.dynamic_entries)]
        assert self.decoder.header_table.dynamic_entries == self.validator.header_table.dynamic_entries
        # Stable sort preserves the order of duplicate names and their values.
        return {"table_updates": updates, "fields": sorted(fields, key=lambda field: field["name"])}


def http_order_form(http):
    assert http["protocol"] == "h2", "HTTP/1 order is not included in this allowance"
    output = copy.deepcopy(http)
    proof = HpackOrderProof()
    assert len(output["requests"]) == 2, "missing/reordered request evidence"
    for request in output["requests"]:
        block = bytes.fromhex(request.pop("hpack_block"))
        assert request.pop("hpack_sha256") == hashlib.sha256(block).hexdigest(), "HPACK digest mismatch"
        request["hpack_order_proof"] = proof.block(block, request["headers"])
        request["headers"] = sorted(request["headers"], key=lambda field: field[0])
        frames = request["header_frames"]
        assert frames and frames[0]["type"] == 1
        assert all(frame["type"] == 9 for frame in frames[1:])
        assert all(bool(frame["flags"] & 4) == (i == len(frames) - 1) for i, frame in enumerate(frames))
        lengths = [frame["length"] - len(bytes.fromhex(frame.get("prefix", ""))) -
                   len(bytes.fromhex(frame.get("padding", ""))) for frame in frames]
        assert min(lengths) >= 0 and sum(lengths) == len(block), "inconsistent frame/block lengths"
        # Only a proven dynamic-reference width delta may alter the final
        # fragment length. All other boundaries, flags and padding stay exact.
        frames[-1]["length"] -= len(block)
    return output


def _single(directory, suffix):
    paths = list((directory / "runtime").glob(f"*.{suffix}.json"))
    assert len(paths) == 1, f"missing/duplicate paired {suffix} evidence"
    return json.loads(paths[0].read_text())


def origin_http_wire(http):
    """Reconstruct observed header/control frames to bind B output to A input."""
    if http["protocol"] == "http/1.1":
        return "".join(request["head"] for request in http["requests"]).encode("ascii")
    assert http["protocol"] == "h2"
    wire = bytearray(PREFACE)
    for control in http["controls"]:
        wire.extend(frame(control["type"], control["flags"], control["stream"], bytes.fromhex(control["payload"])))
    for request in http["requests"]:
        block = bytes.fromhex(request["hpack_block"])
        assert hashlib.sha256(block).hexdigest() == request["hpack_sha256"]
        position = 0
        for layout in request["header_frames"]:
            prefix, padding = [bytes.fromhex(layout.get(key, "")) for key in ("prefix", "padding")]
            size = layout["length"] - len(prefix) - len(padding)
            assert size >= 0 and position + size <= len(block)
            payload = prefix + block[position:position + size] + padding
            wire.extend(frame(layout["type"], layout["flags"], request["stream"], payload))
            position += size
        assert position == len(block)
    return bytes(wire)


def order_allowance(result, directory):
    report = {"policy": POLICY, "accepted": False, "layers": []}
    try:
        assert not result.get("error") and not result.get("evidence_error"), "failed request/capture"
        assert paired_match(result), "same-request B comparison must match strictly"
        assert result.get("tls_limitations") == [], "unsupported TLS capability"
        samples = [json.loads((directory / f"{sample}.json").read_text())
                   for sample in ("direct-1", "direct-2", "bridged")]
        assert all(all(sample.get(layer) for layer in ("tls", "http", "tcp")) for sample in samples), "missing layer"
        # Re-check actual paired captures rather than trusting a pass Boolean.
        inbound, outbound = [_single(directory, side) for side in ("inbound", "outbound")]
        assert inbound.get("tls") and equal(inbound["tls"], outbound.get("tls")), "B changed TLS fingerprint/order"
        assert equal(outbound["tls"], samples[2]["tls"]), "B TLS output differs from A capture"
        assert equal(_single(directory, "report")["comparison"], result["paired_tls"]), "paired TLS report mismatch"
        mapping = result["mapping"]
        assert mapping["public"].startswith("b.test:") and mapping["upstream"].startswith("a.test:")
        paired = compare_paired_http(_single(directory, "http"), mapping["public"], mapping["upstream"])
        assert paired["pass"] and equal(paired, result["paired_http"]), "B changed HTTP fingerprint/order"
        at_origin = paired_http_form(origin_http_wire(samples[2]["http"]), samples[2]["http"]["protocol"],
                                     mapping["public"].encode(), mapping["upstream"].encode())
        assert equal(at_origin, paired["outbound"]), "B HTTP output differs from A capture"
        for layer in ("tls", "http", "tcp"):
            values = [sample[layer] for sample in samples]
            if all(equal(values[0], value) for value in values[1:]):
                continue
            assert layer != "tcp", "TCP variance is never an order allowance"
            normalize = tls_order_form if layer == "tls" else http_order_form
            normalized = [normalize(value) for value in values]
            assert all(equal(normalized[0], value) for value in normalized[1:]), f"{layer} differs beyond permitted order"
            report["layers"].append(layer)
        assert report["layers"], "no proven independent order variance"
        report.update(accepted=True, reason="independent order variance; same-request B wire checks match")
    except (AssertionError, KeyError, IndexError, TypeError, ValueError, OSError, hpack.HPACKError) as error:
        report["layers"] = []
        report["reason"] = str(error) or type(error).__name__
    return report
