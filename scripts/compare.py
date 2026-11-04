#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Record repeated, explicitly non-equivalent URL workloads without rankings."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / '.build'
ITERATIONS = 100000  # Existing Node/Python drivers have this fixed count.
NUMBER = r'(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?'
ROW = re.compile(rf'^([^:]+):\s*(\d+)\s+ops in\s+({NUMBER})\s+s\s+\(\s*({NUMBER})\s+ops/sec,\s*({NUMBER})\s+ns/op,\s*checksum=(\d+)\)$')


def executable(value):
    found = shutil.which(value) if '/' not in value else str((ROOT/value).resolve())
    if not found or not Path(found).is_file():
        raise ValueError(f'executable not found: {value}')
    return found


def invoke(command, timeout=120):
    result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f'command failed ({result.returncode}): {command!r}\n{result.stderr[:4096]}')
    return result


def text(*command):
    return invoke(list(command), timeout=20).stdout.strip()


def parse_rows(output, expected):
    rows = {}
    for line in output.splitlines():
        match = ROW.fullmatch(line.strip())
        if not match:
            continue
        name, count, elapsed, ops, ns, checksum = match.groups()
        if name in rows:
            raise ValueError(f'duplicate benchmark row {name}')
        count, elapsed, ops, ns, checksum = int(count), float(elapsed), float(ops), float(ns), int(checksum)
        if count != ITERATIONS or not all(math.isfinite(v) for v in [elapsed, ops, ns]) or elapsed <= 0 or ops <= 0 or ns < 0:
            raise ValueError(f'invalid timing/count in {name}')
        if name not in expected or checksum != ITERATIONS * expected[name]:
            raise ValueError(f'unexpected row/checksum in {name}: {checksum}')
        rows[name] = dict(iterations=count, elapsed_seconds=elapsed, reported_ops_sec=ops,
                          reported_ns_op=ns, checksum=checksum)
    if set(rows) != set(expected):
        raise ValueError(f'benchmark rows differ: expected {sorted(expected)}, got {sorted(rows)}')
    return rows


def cpu_model():
    path = Path('/proc/cpuinfo')
    if path.exists():
        for line in path.read_text().splitlines():
            if line.startswith('model name'):
                return line.split(':', 1)[1].strip()
    return platform.processor()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--goose', default=os.environ.get('GOOSE', '.toolchain/goose/build/goose'))
    parser.add_argument('--cc', default=os.environ.get('CC', 'cc'))
    parser.add_argument('--samples', type=int, default=3)
    parser.add_argument('--warmups', type=int, default=1)
    parser.add_argument('--output', default='.build/compare_results.json')
    args = parser.parse_args()
    if not 3 <= args.samples <= 20 or not 1 <= args.warmups <= 5:
        parser.error('--samples must be 3..20 and --warmups 1..5')
    BUILD.mkdir(exist_ok=True)
    output = ROOT/args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)
    goose, cc = executable(args.goose), executable(args.cc)
    source_names = ['url.goose', 'address.goose', 'scripts/sanitizer-cc.py', 'bench/bench.goose', 'bench/curl_bench.c', 'bench/node_bench.js',
                    'bench/python_bench.py', 'scripts/compare.py', 'GOOSE_REVISION']
    source_hashes = {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in source_names}
    build_command = [goose, 'build', '-O2', '--standalone', '--cc', cc, '-v',
                     '-o', str(BUILD/'bench'), 'bench/bench.goose']
    build = invoke(build_command, timeout=240)
    parse_checksum = 8443 + len('/api/v1/resource/items')
    drivers = {'goose': dict(command=[str(BUILD/'bench'), str(ITERATIONS)], expected={
        'bench_parse': parse_checksum, 'bench_parse_view': parse_checksum,
        'bench_resolve': len('/g'), 'bench_dot_remove': len('/a/h/i'),
        'bench_query_parse': 6, 'bench_origin': len('https://example.com:8443'), 'bench_query_sort': 6})}
    skipped = {}
    builds = {'goose': dict(command=build_command, stdout=build.stdout, stderr=build.stderr)}
    pkg_config = shutil.which('pkg-config')
    curl_version = None
    if pkg_config and subprocess.run([pkg_config, '--exists', 'libcurl'], timeout=20).returncode == 0:
        curl_flags = shlex.split(text(pkg_config, '--cflags', '--libs', 'libcurl'))
        curl_command = [cc, '-std=c11', '-D_POSIX_C_SOURCE=200809L', '-O2', 'bench/curl_bench.c',
                        *curl_flags, '-o', str(BUILD/'curl_bench')]
        built = invoke(curl_command, timeout=120)
        builds['curl'] = dict(command=curl_command, stdout=built.stdout, stderr=built.stderr)
        curl_version = text(pkg_config, '--modversion', 'libcurl')
        drivers['curl'] = dict(command=[str(BUILD/'curl_bench'), str(ITERATIONS)],
                               expected={'curl_url parse': 8443, 'curl_url resolve': 1})
    else:
        skipped['curl'] = 'libcurl development package/pkg-config unavailable'
    node = shutil.which('node')
    node_version = None
    if node:
        node_version = text(node, '--version')
        drivers['node'] = dict(command=[node, 'bench/node_bench.js'],
                               expected={'Node.js URL parse': 8443, 'Node.js URL resolve': len('/g')})
    else:
        skipped['node'] = 'node executable unavailable'
    drivers['python'] = dict(command=[sys.executable, 'bench/python_bench.py'],
        expected={'Python urlsplit parse': 8443, 'Python urljoin resolve': len('http://a/g?y#s')})
    result = dict(schema=1, recorded_utc=datetime.now(timezone.utc).isoformat(),
        source_revision=text('git', 'rev-parse', 'HEAD'), source_dirty=bool(text('git', 'status', '--porcelain')),
        source_sha256=source_hashes,
        binary_sha256={name: hashlib.sha256((BUILD/name).read_bytes()).hexdigest()
                       for name in ['bench', 'curl_bench'] if (BUILD/name).exists() and (name != 'curl_bench' or 'curl' in drivers)},
        goose_revision=(ROOT/'GOOSE_REVISION').read_text().strip(), goose_version=text(goose, '--version'),
        compiler=cc, compiler_version=text(cc, '--version'), python_version=sys.version,
        node_version=node_version, libcurl_pkgconfig_version=curl_version,
        platform=platform.platform(), machine=platform.machine(), cpu_model=cpu_model(),
        cpu_count=os.cpu_count(), affinity=sorted(os.sched_getaffinity(0)) if hasattr(os, 'sched_getaffinity') else None,
        shared_host=True, iterations=ITERATIONS, samples=args.samples, excluded_process_warmups=args.warmups,
        build=builds, skipped=skipped, raw_samples={name: [] for name in drivers},
        boundaries=[
            'Different contracts/work are measured. No universal ranking or speedup claim is valid.',
            'Goose reports owned/view parsing, already-parsed-base resolution, dot removal and query/origin helpers.',
            'libcurl allocates a CURLU per operation and reparses the base during each resolution; its checksum reads different fields.',
            'Node uses the WHATWG URL parser; every sample is a fresh process including its own JIT activity within the timed loop.',
            'Python repeatedly calls urllib.parse on identical strings; its URL splitting cache is not cleared.',
            'Driver clocks exclude process startup and report their own loop durations. Whole-process warmups do not preserve JIT/cache state across processes.',
            'One fixed input per workload; checksums prevent unchecked parse failures but do not establish parser semantic equivalence.',
            'Goose -O2 selects language inlining; verbose build output records actual C commands. Native comparison uses explicit -O2.',
            'Samples rotate driver order; shared-host scheduling/noise remains. No performance thresholds are used.'])
    for name, driver in drivers.items():
        for _ in range(args.warmups):
            warm = invoke(driver['command'])
            if warm.stderr:
                raise ValueError(f'{name} warmup emitted stderr: {warm.stderr[:4096]}')
            parse_rows(warm.stdout, driver['expected'])
    names = list(drivers)
    for sample in range(args.samples):
        for name in names[sample % len(names):] + names[:sample % len(names)]:
            driver = drivers[name]
            measured = invoke(driver['command'])
            if measured.stderr:
                raise ValueError(f'{name} emitted stderr: {measured.stderr[:4096]}')
            rows = parse_rows(measured.stdout, driver['expected'])
            result['raw_samples'][name].append(dict(command=driver['command'], stdout=measured.stdout,
                                                     stderr=measured.stderr, rows=rows))
    if source_hashes != {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in source_names}:
        raise RuntimeError('source changed during measurement; result discarded')
    result['medians_ns_op'] = {name: {key: statistics.median(sample['rows'][key]['reported_ns_op']
        for sample in samples) for key in samples[0]['rows']} for name, samples in result['raw_samples'].items()}
    payload = json.dumps(result, indent=2).replace(str(ROOT), '<SOURCE>').replace(str(Path.home()), '<HOME>')
    output.write_text(payload+'\n')
    print('Recorded non-equivalent workloads:', ', '.join(drivers))
    print('Raw samples and provenance:', output)


if __name__ == '__main__':
    main()
