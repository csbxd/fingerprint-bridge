"""Independent, same-connection B input/output check; never replaces A baselines.

Only mapped authority/origin/referer value bytes and their required encoded
lengths may differ. Header order, HPACK representation, Huffman flags, dynamic
indices, settings and frame layout remain significant.
"""
import hashlib
import hpack
from lab import PREFACE


def mapped(name, value, public, upstream):
    if name in (b"host", b":authority") and value == public:
        return upstream
    if name in (b"origin", b"referer"):
        for prefix in (b"https://", b"//"):
            old = prefix + public
            if value == old or (value.startswith(old) and value[len(old):len(old)+1] in (b"/", b"?", b"#")):
                return prefix + upstream + value[len(old):]
    return value


def integer(data, position, bits):
    mask = (1 << bits) - 1
    value = data[position] & mask
    position += 1
    if value == mask:
        shift = 0
        while True:
            byte = data[position]; position += 1
            value += (byte & 127) << shift
            if not byte & 128:
                break
            shift += 7
            assert shift <= 56, "oversized HPACK integer"
    return value, position


def string(data, position):
    start = position
    huffman = bool(data[position] & 128)
    size, position = integer(data, position, 7)
    end = position + size
    assert end <= len(data), "truncated HPACK string"
    return {"huffman": huffman, "wire": data[start:end].hex()}, end


def representations(block, headers, public, upstream):
    tokens, position, field = [], 0, 0
    while position < len(block):
        byte = block[position]
        bits = 7 if byte & 128 else 6 if byte & 64 else 5 if byte & 32 else 4
        index, position = integer(block, position, bits)
        kind = "indexed" if bits == 7 else "incremental" if bits == 6 else "table-size" if bits == 5 else "never" if byte & 16 else "without"
        token = {"kind": kind, "index": index}
        if kind == "table-size":
            tokens.append(token); continue
        name, value = headers[field]; field += 1
        if kind != "indexed":
            if not index:
                token["name"], position = string(block, position)
            token["value"], position = string(block, position)
            # Canonicalize only the three permitted mapped fields. The caller
            # also applies this to the already-rewritten outgoing authority.
            normalized = mapped(name, value, public, upstream)
            permitted = name in (b"host", b":authority", b"origin", b"referer") and (
                normalized != value or mapped(name, value, upstream, public) != value)
            if permitted:
                token["value"] = {"huffman": token["value"]["huffman"], "mapped": normalized.hex()}
        tokens.append(token)
    assert field == len(headers), "HPACK field count"
    return tokens


def normalize(data, protocol, public, upstream):
    if protocol == "http/1.1":
        assert data.endswith(b"\r\n\r\n"), "truncated HTTP/1 headers"
        heads = []
        for head in data[:-4].split(b"\r\n\r\n"):
            lines = head.split(b"\r\n")
            assert lines[0].startswith(b"GET "), "paired lab only accepts bodyless GET"
            for i, line in enumerate(lines[1:], 1):
                name, separator, raw = line.partition(b":")
                assert separator
                value = raw.lstrip(b" \t")
                lines[i] = name + separator + raw[:len(raw)-len(value)] + mapped(name.lower(), value, public, upstream)
            heads.append(b"\r\n".join(lines).hex())
        assert len(heads) == 2, "missing HTTP/1 request"
        return {"requests": heads}
    assert protocol == "h2" and data.startswith(PREFACE), "missing HTTP/2 preface"
    decoder, position = hpack.Decoder(), len(PREFACE)
    controls, requests, blocks, layouts = [], [], {}, {}
    while position < len(data):
        assert position + 9 <= len(data), "truncated frame header"
        size = int.from_bytes(data[position:position+3], "big")
        kind, flags = data[position+3:position+5]
        stream = int.from_bytes(data[position+5:position+9], "big")
        payload = data[position+9:position+9+size]; position += 9+size
        assert len(payload) == size
        if kind in (4, 2, 8) and not (kind == 4 and flags & 1):
            controls.append([kind, flags, stream, payload.hex()])
        if kind not in (1, 9):
            assert kind != 0, "unexpected request body"
            continue
        prefix, padding = 0, 0
        if kind == 1:
            padding = payload[0] if flags & 8 else 0
            prefix = (1 if flags & 8 else 0) + (5 if flags & 32 else 0)
        assert prefix + padding <= size
        fragment = payload[prefix:size-padding if padding else None]
        blocks.setdefault(stream, bytearray()).extend(fragment)
        layouts.setdefault(stream, []).append({"type": kind, "flags": flags, "length": size,
            "prefix": payload[:prefix].hex(), "padding": payload[size-padding:].hex() if padding else ""})
        if flags & 4:
            block = bytes(blocks.pop(stream))
            headers = decoder.decode(block, raw=True)
            layout = layouts.pop(stream)
            # Only the final fragment absorbs the mapped-value byte delta.
            layout[-1]["length"] -= len(block)
            requests.append({"stream": stream,
                "headers": [[k.hex(), mapped(k, v, public, upstream).hex()] for k, v in headers],
                "representations": representations(block, headers, public, upstream), "frames": layout})
    assert not blocks and len(requests) == 2, "incomplete HTTP/2 requests"
    return {"controls": controls, "requests": requests}


def compare(document, public, upstream):
    assert not any(document[k]["truncated"] for k in ("inbound", "outbound")), "truncated HTTP capture"
    left, right = [normalize(bytes(document[k]["bytes"]), document["protocol"], public.encode(), upstream.encode()) for k in ("inbound", "outbound")]
    return {"pass": left == right, "scope": "same connection B input/output, permitted authority value changes only",
            "inbound": left, "outbound": right,
            "wire_sha256": {k: hashlib.sha256(bytes(document[k]["bytes"])).hexdigest() for k in ("inbound", "outbound")}}
