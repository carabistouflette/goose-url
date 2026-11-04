#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Seeded property/shared-domain differential checks; not coverage-guided fuzzing."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import string
import subprocess
import sys
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / '.build'


def executable(value):
    found = shutil.which(value) if '/' not in value else str((ROOT / value).resolve())
    if not found or not Path(found).is_file():
        raise ValueError(f'executable not found: {value}')
    return found


def run(command, *, data=None, timeout=120):
    result = subprocess.run(command, cwd=ROOT, input=data, capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode or result.stderr:
        raise RuntimeError(f'command failed ({result.returncode}): {command!r}\n{result.stderr[:4096]}')
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--goose', default=os.environ.get('GOOSE', '.toolchain/goose/build/goose'))
    parser.add_argument('--cc', default=os.environ.get('CC', 'cc'))
    parser.add_argument('--seed', type=int, default=491)
    parser.add_argument('--cases', type=int, default=5000)
    parser.add_argument('--query-cases', type=int, default=1000)
    args = parser.parse_args()
    if not 1 <= args.cases <= 100000 or not 1 <= args.query_cases <= 100000:
        parser.error('case counts must be in 1..100000')
    BUILD.mkdir(exist_ok=True)
    report = BUILD / 'fuzz-results.json'
    report.unlink(missing_ok=True)
    failure = BUILD / 'fuzz-failure.txt'
    failure.unlink(missing_ok=True)
    goose, cc = executable(args.goose), executable(args.cc)
    binary = BUILD / 'fuzz'
    source_names = ['url.goose', 'address.goose', 'scripts/sanitizer-cc.py', 'tests/fuzz.goose', 'scripts/fuzz.py', 'GOOSE_REVISION']
    source_hashes = {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in source_names}
    command = [goose, 'build', '-O2', '--cc', cc, '--standalone', '-o', str(binary), 'tests/fuzz.goose']
    subprocess.run(command, cwd=ROOT, check=True, timeout=240)
    properties = run([str(binary)])
    if 'all goose-url property tests passed' not in properties:
        raise RuntimeError('property driver did not confirm completion')
    rng = random.Random(args.seed)
    counts = {'resolution': 0, 'query': 0, 'random_text': 0}
    digest = hashlib.sha256()

    def batch(commands, check, kind):
        for start in range(0, len(commands), 1000):
            lines = commands[start:start + 1000]
            data = ''.join(line + '\n' for line in lines)
            digest.update(data.encode())
            try:
                output = run([str(binary), '--stdin'], data=data).splitlines()
                if len(output) != len(lines):
                    raise ValueError(f'expected {len(lines)} output lines, got {len(output)}')
            except Exception:
                failure.write_text(data)
                raise
            for offset, (line, actual) in enumerate(zip(lines, output)):
                try:
                    check(line, actual)
                except Exception as error:
                    failure.write_text(line + '\n')
                    raise ValueError(f'{kind} seed={args.seed} index={start + offset}; '
                                     f'reproducer={failure}: {error}') from error
                counts[kind] += 1

    bases = ['http://a/b/c/d;p?q', 'https://example.com/dir/file',
             'http://127.0.0.1:8080/v1/api', 'ftp://ftp.example.com/pub/', 'http://[::1]/a/b/c']
    refs = ['g:h', 'g', './g', 'g/', '/g', '//g', '?y', 'g?y', '#s', 'g#s',
            'g?y#s', ';x', 'g;x', 'g;x?y#s', '', '.', './', '..', '../', '../g',
            '../..', '../../', '../../g', 'foo/bar/../baz', './../x', '/./y']

    def resolution(line, actual):
        base, ref = line[2:].split(' ', 1)
        expected = 'OK ' + urllib.parse.urljoin(base, ref)
        if actual != expected:
            raise ValueError(f'expected {expected!r}, got {actual!r}')

    batch([f'R {base} {ref}' for base in bases for ref in refs], resolution, 'resolution')
    queries = ['key=value&foo=bar&flag=', 'a=1&b=2&c=3', 'search=goose+language&sort=date',
               'empty=&blank', 'special=%26%3D%25%2B&hello=world%21', 'multi=first&multi=second']
    alphabet = string.ascii_letters + string.digits + '-_.~ +='
    while len(queries) < args.query_cases:
        pairs = [(''.join(rng.choice(string.ascii_letters) for _ in range(rng.randint(1, 8))),
                  ''.join(rng.choice(alphabet) for _ in range(rng.randint(0, 10))))
                 for _ in range(rng.randint(1, 6))]
        queries.append(urllib.parse.urlencode(pairs))

    def query(line, actual):
        if not actual.startswith('OK '):
            raise ValueError(f'query rejected: {actual!r}')
        expected = urllib.parse.parse_qsl(line[2:], keep_blank_values=True)
        got = urllib.parse.parse_qsl(actual[3:], keep_blank_values=True)
        if got != expected:
            raise ValueError(f'expected {expected!r}, got {got!r}')

    batch(['Q ' + value for value in queries[:args.query_cases]], query, 'query')
    charset = string.ascii_letters + string.digits + "-_.~:/?#[]@!$&'()*+,;=%" + '\x00\xff \t'
    candidates = []
    for _ in range(args.cases):
        if rng.randrange(2):
            candidate = ''.join(rng.choice(charset) for _ in range(rng.randint(1, 150)))
        else:
            scheme = rng.choice(['http', 'https', 'ftp', 'ws', 'urn', 'custom', ''])
            host = rng.choice(['localhost', 'example.com', '127.0.0.1', '[::1]', 'foo-bar', ''])
            path = rng.choice(['', '/', '/a/b', '/a/./b/../c', '/test?query#frag'])
            candidate = (scheme + '://' if scheme else '//') + host + path
        candidates.append('P ' + candidate)

    def parse(_, actual):
        if actual != 'ERR' and not actual.startswith('OK '):
            raise ValueError(f'invalid parse result: {actual!r}')

    batch(candidates, parse, 'random_text')
    if source_hashes != {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in source_names}:
        raise RuntimeError('source changed during fuzz campaign; result discarded')
    result = dict(schema=1, status='passed', seed=args.seed, counts=counts,
                  corpus_sha256=digest.hexdigest(), binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  source_revision=run(['git', 'rev-parse', 'HEAD']).strip(),
                  source_dirty=bool(run(['git', 'status', '--porcelain']).strip()),
                  source_sha256=source_hashes,
                  python_version=sys.version, goose_version=run([goose, '--version']).strip(),
                  goose_revision=(ROOT/'GOOSE_REVISION').read_text().strip(),
                  compiler=cc, compiler_version=run([cc, '--version']).strip(), build_command=command,
                  scope='Shared-domain resolution/query checks and seeded text robustness; not a general RFC oracle or coverage-guided fuzzing.')
    payload = json.dumps(result, indent=2).replace(str(ROOT), '<SOURCE>').replace(str(Path.home()), '<HOME>')
    report.write_text(payload + '\n')
    print(f'fuzz checks passed: seed={args.seed}, counts={counts}; report={report.relative_to(ROOT)}')


if __name__ == '__main__':
    main()
