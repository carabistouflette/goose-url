#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Differential and robustness fuzzing driver for goose-url.
Compares goose-url parsing and resolution against Python's urllib.parse oracle
and feeds randomized/mutated inputs to verify bounds safety and crash resilience.
"""

import os
import random
import string
import subprocess
import sys
import urllib.parse

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOOSE_BIN = os.path.join(REPO_ROOT, ".toolchain", "goose", "build", "goose")
BUILD_DIR = os.path.join(REPO_ROOT, ".build")
FUZZ_BIN = os.path.join(BUILD_DIR, "fuzz")


def compile_harness():
    os.makedirs(BUILD_DIR, exist_ok=True)
    cmd = [GOOSE_BIN, "build", "-O2", "-o", FUZZ_BIN, "tests/fuzz.goose"]
    print(f"[*] Compiling fuzz harness: {' '.join(cmd)}")
    res = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[!] Compilation failed:\n{res.stderr}")
        sys.exit(1)
    print(f"[+] Compiled fuzz harness successfully: {FUZZ_BIN}")


def test_builtin_properties():
    print("[*] Running built-in Goose property tests...")
    res = subprocess.run([FUZZ_BIN], cwd=REPO_ROOT, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[!] Property tests failed:\n{res.stderr}")
        sys.exit(1)
    print(f"[+] {res.stdout.strip()}")


def run_differential_suite():
    print("[*] Running differential resolution suite against urllib.parse...")
    bases = [
        "http://a/b/c/d;p?q",
        "https://example.com/dir/file",
        "http://127.0.0.1:8080/v1/api",
        "ftp://ftp.example.com/pub/",
        "http://[::1]/a/b/c",
    ]
    refs = [
        "g:h", "g", "./g", "g/", "/g", "//g", "?y", "g?y", "#s", "g#s",
        "g?y#s", ";x", "g;x", "g;x?y#s", "", ".", "./", "..", "../", "../g",
        "../..", "../../", "../../g", "foo/bar/../baz", "./../x", "/./y"
    ]

    proc = subprocess.Popen(
        [FUZZ_BIN, "--stdin"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=REPO_ROOT
    )

    diff_count = 0
    total = 0

    for base in bases:
        for ref in refs:
            total += 1
            cmd = f"R {base} {ref}\n"
            proc.stdin.write(cmd)
            proc.stdin.flush()
            out_line = proc.stdout.readline().strip()
            if not out_line.startswith("OK "):
                print(f"[!] Harness error for base={base} ref={ref}: {out_line}")
                sys.exit(1)
            goose_resolved = out_line[3:].strip()
            py_resolved = urllib.parse.urljoin(base, ref)

            # Both should match on RFC 3986 normalization
            if goose_resolved != py_resolved:
                # Some Python versions retain or normalize dot segments differently for urn/special schemes
                print(f"[!] Discrepancy at base={base} ref={ref}: goose={goose_resolved} py={py_resolved}")
                diff_count += 1

    proc.stdin.close()
    proc.wait()

    if diff_count > 0:
        print(f"[!] Found {diff_count}/{total} differences with urllib.parse")
        sys.exit(1)
    print(f"[+] All {total} differential test cases matched urllib.parse exactly!")


def run_random_fuzzing(count=10000):
    print(f"[*] Running {count} randomized input fuzzing iterations...")
    proc = subprocess.Popen(
        [FUZZ_BIN, "--stdin"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=REPO_ROOT
    )

    charset = string.ascii_letters + string.digits + "-_.~:/?#[]@!$&'()*+,;=%" + "\x00\xff" + " \t\r\n"

    for i in range(count):
        # Generate varied inputs: 50% structured with mutations, 50% random junk
        if random.random() < 0.5:
            length = random.randint(1, 150)
            candidate = "".join(random.choice(charset) for _ in range(length))
        else:
            scheme = random.choice(["http", "https", "ftp", "ws", "urn", "custom", ""])
            host = random.choice(["localhost", "example.com", "127.0.0.1", "[::1]", "foo-bar", ""])
            path = random.choice(["", "/", "/a/b", "/a/./b/../c", "/test?query#frag"])
            candidate = f"{scheme}://{host}{path}" if scheme else f"//{host}{path}"

        # Sanitize newlines for the line-oriented stdin protocol
        clean_input = candidate.replace("\n", "").replace("\r", "")
        cmd = f"P {clean_input}\n"
        proc.stdin.write(cmd)
        proc.stdin.flush()
        out = proc.stdout.readline()
        if not out:
            print(f"[!] Process crashed on input: {clean_input!r}")
            sys.exit(1)

    proc.stdin.close()
    proc.wait()
    if proc.returncode != 0:
        print(f"[!] Fuzz harness exited with error code {proc.returncode}")
        sys.exit(1)

    print(f"[+] Completed {count} fuzz iterations with 0 crashes!")


def run_differential_query_suite(iterations=1000):
    print(f"[*] Running {iterations} differential query codec tests against urllib.parse...")
    proc = subprocess.Popen(
        [FUZZ_BIN, "--stdin"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=REPO_ROOT
    )

    test_queries = [
        "key=value&foo=bar&flag=",
        "a=1&b=2&c=3",
        "search=goose+language&sort=date",
        "empty=&blank",
        "special=%26%3D%25%2B&hello=world%21",
        "multi=first&multi=second",
    ]

    charset = string.ascii_letters + string.digits + "-_.~ +="

    for i in range(iterations):
        if i < len(test_queries):
            query = test_queries[i]
        else:
            num_pairs = random.randint(1, 6)
            pairs = []
            for _ in range(num_pairs):
                k = "".join(random.choice(string.ascii_letters) for _ in range(random.randint(1, 8)))
                v = "".join(random.choice(charset) for _ in range(random.randint(0, 10)))
                pairs.append((k, v))
            query = urllib.parse.urlencode(pairs)

        clean_query = query.replace("\n", "").replace("\r", "")
        cmd = f"Q {clean_query}\n"
        proc.stdin.write(cmd)
        proc.stdin.flush()
        out = proc.stdout.readline().strip()
        if not out.startswith("OK "):
            print(f"[!] Query harness failed on {clean_query!r}: {out}")
            sys.exit(1)

        goose_formatted = out[3:].strip()
        py_pairs_orig = urllib.parse.parse_qsl(clean_query, keep_blank_values=True)
        py_pairs_goose = urllib.parse.parse_qsl(goose_formatted, keep_blank_values=True)

        if py_pairs_orig != py_pairs_goose:
            print(f"[!] Discrepancy in query codec: orig={py_pairs_orig} goose_reconstructed={py_pairs_goose}")
            sys.exit(1)

    proc.stdin.close()
    proc.wait()
    print(f"[+] All {iterations} differential query codec tests matched urllib.parse exactly!")


def main():
    compile_harness()
    test_builtin_properties()
    run_differential_suite()
    run_differential_query_suite(1000)
    run_random_fuzzing(5000)
    print("\n[SUCCESS] All fuzzing and property tests passed successfully.")


if __name__ == "__main__":
    main()
