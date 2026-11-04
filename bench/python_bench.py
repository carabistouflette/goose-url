# SPDX-License-Identifier: Apache-2.0
# Python urllib.parse benchmark
import time
import urllib.parse

iterations = 100000
url_str = "https://user:pass@example.com:8443/api/v1/resource/items?filter=active&sort=desc#section-1"

# 1. Bench Parse
start = time.perf_counter()
checksum = 0
for _ in range(iterations):
    u = urllib.parse.urlsplit(url_str)
    if u.port:
        checksum += u.port
elapsed = time.perf_counter() - start
ops = iterations / elapsed
ns = (elapsed / iterations) * 1e9
print(f"Python urlsplit parse:{iterations:8d} ops in {elapsed:.6f} s ({ops:9.0f} ops/sec, {ns:6.1f} ns/op, checksum={checksum})")

# 2. Bench Resolve
base_str = "http://a/b/c/d;p?q"
ref_str = "../../g?y#s"
start = time.perf_counter()
resolve_checksum = 0
for _ in range(iterations):
    res = urllib.parse.urljoin(base_str, ref_str)
    resolve_checksum += len(res)
elapsed = time.perf_counter() - start
ops = iterations / elapsed
ns = (elapsed / iterations) * 1e9
print(f"Python urljoin resolve:{iterations:7d} ops in {elapsed:.6f} s ({ops:9.0f} ops/sec, {ns:6.1f} ns/op, checksum={resolve_checksum})")
