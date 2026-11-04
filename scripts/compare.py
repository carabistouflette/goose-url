#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Multi-ecosystem comparative benchmark runner for goose-url.
Compares goose-url against:
- libcurl curl_url (C)
- Node.js URL (Ada backend)
- Python 3 urllib.parse
"""

import json
import os
import re
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD_DIR = os.path.join(REPO_ROOT, ".build")
GOOSE_BIN = os.path.join(REPO_ROOT, ".toolchain", "goose", "build", "goose")


def build_binaries():
    os.makedirs(BUILD_DIR, exist_ok=True)
    # Build goose bench
    subprocess.run([GOOSE_BIN, "build", "-O2", "-o", os.path.join(BUILD_DIR, "bench"), "bench/bench.goose"],
                   cwd=REPO_ROOT, check=True, capture_output=True)
    # Build curl bench
    pkg = subprocess.check_output(["pkg-config", "--cflags", "--libs", "libcurl"], text=True).strip().split()
    cmd = ["gcc", "-O3", "bench/curl_bench.c"] + pkg + ["-o", os.path.join(BUILD_DIR, "curl_bench")]
    subprocess.run(cmd, cwd=REPO_ROOT, check=True, capture_output=True)


def run_benchmark(iterations=100000):
    results = {}

    # 1. goose-url
    goose_out = subprocess.check_output([os.path.join(BUILD_DIR, "bench"), str(iterations)], text=True)
    for line in goose_out.splitlines():
        m = re.search(r'(bench_\w+):\s+\d+\s+ops in [\d\.]+ s \((\d+) ops/sec,\s+(\d+) ns/op', line)
        if m:
            name, ops, ns = m.groups()
            results[f"goose-url ({name})"] = {"ops_sec": int(ops), "ns_op": float(ns)}

    # 2. curl_url (C)
    curl_out = subprocess.check_output([os.path.join(BUILD_DIR, "curl_bench"), str(iterations)], text=True)
    for line in curl_out.splitlines():
        m = re.search(r'curl_url (\w+):\s+\d+\s+ops in [\d\.]+ s \((\d+) ops/sec,\s+([\d\.]+) ns/op', line)
        if m:
            name, ops, ns = m.groups()
            results[f"libcurl C (curl_url {name})"] = {"ops_sec": int(ops), "ns_op": float(ns)}

    # 3. Node.js URL (Ada)
    if os.path.exists("/usr/bin/node"):
        node_out = subprocess.check_output(["node", "bench/node_bench.js"], cwd=REPO_ROOT, text=True)
        for line in node_out.splitlines():
            m = re.search(r'Node\.js URL (\w+):\s+\d+\s+ops in [\d\.]+ s \((\d+) ops/sec,\s+([\d\.]+) ns/op', line)
            if m:
                name, ops, ns = m.groups()
                results[f"Node.js WHATWG (Ada {name})"] = {"ops_sec": int(ops), "ns_op": float(ns)}

    # 4. Python urllib.parse
    py_out = subprocess.check_output([sys.executable, "bench/python_bench.py"], cwd=REPO_ROOT, text=True)
    for line in py_out.splitlines():
        m = re.search(r'Python (\w+) (\w+):\s+\d+\s+ops in [\d\.]+ s \(\s*(\d+) ops/sec,\s+([\d\.]+) ns/op', line)
        if m:
            mod, name, ops, ns = m.groups()
            results[f"Python 3.14 ({mod} {name})"] = {"ops_sec": int(ops), "ns_op": float(ns)}

    return results


def print_table(results):
    print("\n" + "=" * 80)
    print(" " * 22 + "URL PARSING & RESOLUTION BENCHMARK")
    print("=" * 80)
    print(f"{'Implementation':<35} | {'Throughput (ops/sec)':>20} | {'Latency (ns/op)':>16}")
    print("-" * 80)

    # Sort into categories: Parsing and Resolution
    parse_keys = [k for k in results if "parse" in k]
    resolve_keys = [k for k in results if "resolve" in k]

    print("--- URI Parsing ---")
    for k in sorted(parse_keys, key=lambda x: results[x]["ops_sec"], reverse=True):
        r = results[k]
        print(f"{k:<35} | {r['ops_sec']:>20,d} | {r['ns_op']:>16.1f}")

    print("\n--- Reference Resolution ---")
    for k in sorted(resolve_keys, key=lambda x: results[x]["ops_sec"], reverse=True):
        r = results[k]
        print(f"{k:<35} | {r['ops_sec']:>20,d} | {r['ns_op']:>16.1f}")
    print("=" * 80 + "\n")


def main():
    build_binaries()
    res = run_benchmark(100000)
    print_table(res)

    out_file = os.path.join(BUILD_DIR, "compare_results.json")
    with open(out_file, "w") as f:
        json.dump(res, f, indent=2)
    print(f"[+] Saved comparative benchmark results to {out_file}")


if __name__ == "__main__":
    main()
