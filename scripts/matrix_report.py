#!/usr/bin/env python3
"""Aggregate all eight environments and 72 cases; incomplete evidence fails."""
import argparse
import json
from pathlib import Path
import sys

from matrix_config import ARCHITECTURES, CASES, DISTRIBUTIONS, LAYERS, SAMPLES


def layer_status(comparison):
    if not isinstance(comparison, dict):
        return "MISSING"
    if comparison.get("missing_layers"):
        return "MISSING"
    if comparison.get("pass") is True and comparison.get("differences") == [] and comparison.get("missing_layers") == []:
        return "MATCH"
    return "DIFF"


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
        rows.append({"arch": key[0], "distro": key[1], "client": client, "protocol": protocol,
                     "baseline": "stable" if set(baseline) == {"MATCH"} else "unstable/missing",
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
                                 "baseline": "missing", **{layer: "MISSING" for layer in LAYERS}, "paired_tls": "MISSING", "paired_http": "MISSING", "status": "missing-evidence"})
    return rows, errors


def markdown(rows, errors):
    lines = ["# Direct versus bridged fingerprint matrix", "",
             "Two direct connections establish the baseline; one connection goes through B. Each carries two requests.",
             "Distro containers share the runner kernel. This is loopback coverage, not cross-OS TCP cloning or browser certification.", "",
             "B-paired columns compare the very same connection entering/leaving B; they do not replace independent A-side comparisons.", "",
             "| Architecture | Distro | Client | Protocol | Direct baseline | TLS | HTTP | TCP | B-paired TLS | B-paired HTTP | Verdict |",
             "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for row in rows:
        lines.append("| " + " | ".join(str(row[k]) for k in ["arch", "distro", "client", "protocol", "baseline", "tls", "http", "tcp", "paired_tls", "paired_http", "status"]) + " |")
    lines += ["", f"Matches: {sum(r['status']=='match' for r in rows)}/{len(rows)}. Missing, unstable or failed cells are never passes.", "",
              "Artifacts contain actual ClientHello bytes, A-side SYN PCAPs, structured evidence, field differences, client/bridge logs and runtime versions.",
              "HTTP/2 comparison includes HPACK bytes and frame layout; semantic equality alone does not imply a match.", ""]
    if errors:
        lines += ["## Coverage / infrastructure errors", ""] + [f"- {e}" for e in errors]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report-only", action="store_true")
    args = parser.parse_args()
    rows, errors = collect(args.root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(markdown(rows, errors))
    print(args.output.read_text())
    if errors or any(r["status"] == "error" for r in rows):
        return 2
    return 0 if args.report_only or all(r["status"] == "match" for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
