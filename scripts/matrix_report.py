#!/usr/bin/env python3
"""Aggregate all eight environments and 72 cases; incomplete evidence fails."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys

from matrix_config import ARCHITECTURES, CASES, DISTRIBUTIONS, LAYERS, SAMPLES
from order_policy import ACCEPTED, order_allowance


def layer_status(comparison):
    if not isinstance(comparison, dict):
        return "MISSING"
    if comparison.get("missing_layers"):
        return "MISSING"
    if comparison.get("pass") is True and comparison.get("differences") == [] and comparison.get("missing_layers") == []:
        return "MATCH"
    return "DIFF"


def _same_multiset(left, right):
    if not isinstance(left, list) or not isinstance(right, list):
        return False
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))
    return Counter(map(canonical, left)) == Counter(map(canonical, right))


def baseline_instability_reason(result):
    """Describe an unstable direct baseline without changing its verdict."""
    baseline = result.get("baseline", {})
    comparisons = [baseline.get(layer) for layer in LAYERS]
    if any(not isinstance(item, dict) or item.get("missing_layers") for item in comparisons):
        return "missing direct evidence"
    if all(item.get("pass") is True for item in comparisons):
        return ""

    tls_differences = baseline.get("tls", {}).get("differences", [])
    derived = {"/tls/ja3", "/tls/ja3_string"}
    structural = [item for item in tls_differences if item.get("field") not in derived]
    permutation_fields = {"/tls/fields/extensions", "/tls/fields/other_extensions"}
    if structural and all(item.get("field") in permutation_fields and
                          _same_multiset(item.get("baseline"), item.get("observed"))
                          for item in structural):
        return "TLS extension-order permutation"

    http_differences = baseline.get("http", {}).get("differences", [])
    if (not tls_differences and len(http_differences) == 1 and
            http_differences[0].get("field") == "/http/requests"):
        return "HTTP/2 request/HPACK bytes differ"

    changed = [layer.upper() for layer in LAYERS
               if baseline.get(layer, {}).get("pass") is not True]
    return "direct " + "/".join(changed) + " differs"


def stable_mismatch_reason(result):
    """Describe a stable mismatch from captured capabilities, never waive it."""
    if result.get("status") != "mismatch":
        return ""
    tls_differences = result.get("layers", {}).get("tls", {}).get("differences", [])
    fields = {item.get("field") for item in tls_differences}
    point_only = fields and fields <= {
        "/tls/fields/point_formats", "/tls/ja3", "/tls/ja3_string"
    }
    capabilities = result.get("tls_capabilities", {})
    inbound = capabilities.get("inbound", {})
    outbound = capabilities.get("outbound", {})
    groups = inbound.get("groups", [])
    has_binary_group = any((1 <= group <= 14) or group == 0xff02 for group in groups)
    if (point_only and 2 in inbound.get("point_formats", []) and
            2 not in outbound.get("point_formats", []) and not has_binary_group):
        return "deprecated char2 point format advertised without binary group"
    changed = [layer.upper() for layer in LAYERS
               if result.get("layers", {}).get(layer, {}).get("pass") is not True]
    return "bridged " + "/".join(changed) + " differs"


def inspect_summary(document, directory):
    env = document["environment"]
    key = (env["matrix_arch"], env["matrix_distro"])
    assert key[0] in ARCHITECTURES and key[1] in DISTRIBUTIONS, "unexpected environment"
    assert env["architecture"] == {"amd64": "x86_64", "arm64": "aarch64"}[key[0]], "architecture mismatch"
    assert document["tcp_capture_requested"] is True, "TCP capture disabled"
    results = document["results"]
    cases = {(r["client"], r["protocol"]): r for r in results}
    assert len(results) == len(CASES) and set(cases) == set(CASES), "missing/duplicate/unexpected cases"
    rows = []
    for client, protocol in CASES:
        r = cases[(client, protocol)]
        baseline = [layer_status(r.get("baseline", {}).get(layer)) for layer in LAYERS]
        layers = [layer_status(r.get("layers", {}).get(layer)) for layer in LAYERS]
        status = r["status"]
        complete = True
        case_dir = directory / f"{client}-{protocol.replace('/', '-')}"
        for sample in SAMPLES:
            for suffix in ("json", "clienthello.bin", "pcap"):
                evidence = case_dir / f"{sample}.{suffix}"
                if not evidence.is_file() or evidence.stat().st_size == 0:
                    complete = False
        for suffix in ("http.json", "report.json"):
            paired_files = list((case_dir / "runtime").glob(f"*.{suffix}"))
            if len(paired_files) != 1 or paired_files[0].stat().st_size == 0:
                complete = False
        paired_tls = layer_status(r.get("paired_tls"))
        paired_http = r.get("paired_http", {})
        paired_http_status = "MISSING" if "pass" not in paired_http else "MATCH" if paired_http["pass"] and paired_http.get("inbound") == paired_http.get("outbound") else "DIFF"
        if "MISSING" in (paired_tls, paired_http_status):
            complete = False
        if not complete:
            status = "missing-evidence" if status != "error" else "error"
        if status == "match" and (set(baseline) != {"MATCH"} or set(layers + [paired_tls, paired_http_status]) != {"MATCH"}):
            raise AssertionError("summary claims a match despite differences")
        if status == "match-order-variance":
            assert "MISSING" not in baseline + layers, "missing layer cannot receive an order allowance"
            proof = order_allowance(r, case_dir)
            assert proof["accepted"] and proof == r.get("order_allowance"), "unverified order allowance"
            assert paired_tls == paired_http_status == "MATCH", "B-paired difference cannot be waived"
        rows.append({"arch": key[0], "distro": key[1], "client": client, "protocol": protocol,
                     "baseline": "stable" if set(baseline) == {"MATCH"} else "unstable/missing",
                     "baseline_reason": baseline_instability_reason(r),
                     "mismatch_reason": stable_mismatch_reason(r),
                     "order_allowance": r.get("order_allowance"),
                     "raw_status": r.get("raw_status", r["status"]),
                     **dict(zip(LAYERS, layers)), "paired_tls": paired_tls, "paired_http": paired_http_status, "status": status})
    return key, rows


def collect(root):
    environments, errors = {}, []
    for path in sorted(root.rglob("matrix-summary.json")):
        try:
            key, rows = inspect_summary(json.loads(path.read_text()), path.parent)
            if key in environments:
                raise AssertionError(f"duplicate environment {key}")
            environments[key] = rows
        except (KeyError, TypeError, ValueError, AssertionError, OSError) as error:
            errors.append(f"{path}: {error}")
    rows = []
    for arch in ARCHITECTURES:
        for distro in DISTRIBUTIONS:
            key = (arch, distro)
            if key in environments:
                rows.extend(environments[key])
            else:
                errors.append(f"missing environment: {arch}/{distro}")
                for client, protocol in CASES:
                    rows.append({"arch": arch, "distro": distro, "client": client, "protocol": protocol,
                                 "baseline": "missing", "baseline_reason": "missing environment/evidence",
                                 "mismatch_reason": "missing environment/evidence",
                                 **{layer: "MISSING" for layer in LAYERS}, "paired_tls": "MISSING", "paired_http": "MISSING", "status": "missing-evidence"})
    return rows, errors


def markdown(rows, errors):
    lines = ["# Direct versus bridged fingerprint matrix", "",
             "Two direct connections establish the baseline; one connection goes through B. Each carries two requests.",
             "Distro containers share the runner kernel. This is loopback coverage, not cross-OS TCP cloning or browser certification.", "",
             "B-paired columns remain strict. Only proven independent TLS-extension/HTTP2-header order variance receives an explicit allowance; raw DIFF columns remain visible.", "",
             "| Architecture | Distro | Client | Protocol | Direct baseline | TLS | HTTP | TCP | B-paired TLS | B-paired HTTP | Verdict |",
             "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for row in rows:
        lines.append("| " + " | ".join(str(row[k]) for k in ["arch", "distro", "client", "protocol", "baseline", "tls", "http", "tcp", "paired_tls", "paired_http", "status"]) + " |")
    lines += ["", f"Exact matches: {sum(r['status']=='match' for r in rows)}/{len(rows)}.",
              f"Order allowances: {sum(r['status']=='match-order-variance' for r in rows)}/{len(rows)}.",
              f"Accepted: {sum(r['status'] in ACCEPTED for r in rows)}/{len(rows)}. Missing, unproven instability or failed cells never pass.", "",
              "Artifacts contain actual ClientHello bytes, A-side SYN PCAPs, structured evidence, field differences, client/bridge logs and runtime versions.",
              "HTTP/2 comparison includes HPACK bytes and frame layout; semantic equality alone does not imply a match.", ""]
    reasons = Counter(row["baseline_reason"] for row in rows if row["baseline"] != "stable")
    if reasons:
        lines += ["## Direct-baseline instability diagnostics", "",
                  "Raw direct differences remain recorded. Only explicitly proved order variance with strict B-paired equality is accepted.", ""]
        lines += [f"- {reason}: {count}" for reason, count in sorted(reasons.items())]
        lines.append("")
    mismatch_reasons = Counter(row["mismatch_reason"] for row in rows
                               if row["status"] == "mismatch")
    if mismatch_reasons:
        lines += ["## Stable mismatch diagnostics", "",
                  "These counts are diagnostic only; every listed cell remains a strict mismatch.", ""]
        lines += [f"- {reason}: {count}" for reason, count in sorted(mismatch_reasons.items())]
        lines.append("")
    if errors:
        lines += ["## Coverage / infrastructure errors", ""] + [f"- {e}" for e in errors]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--report-only", action="store_true")
    args = parser.parse_args()
    rows, errors = collect(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(markdown(rows, errors))
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps({"rows": rows, "errors": errors,
            "accepted": not errors and all(r["status"] in ACCEPTED for r in rows)}, indent=2) + "\n")
    print(args.output.read_text())
    if errors or any(r["status"] == "error" for r in rows):
        return 2
    return 0 if args.report_only or all(r["status"] in ACCEPTED for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
