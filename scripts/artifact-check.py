#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate the optional URL-policy/artifact caller using real local HTTPS."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import ssl
import subprocess
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "tests/artifact"
CLI = ROOT / "examples/artifact/main.goose"


def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, timeout=600, **kwargs)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sources():
    paths = [ROOT / "url.goose", ROOT / "address.goose", Path(__file__),
             *HERE.glob("*.c"), *CLI.parent.glob("*.goose")]
    return {str(p.relative_to(ROOT)): sha(p) for p in sorted(paths)}


def dependencies():
    result = {}
    for name, source in re.findall(r'import\s+(\w+)\s+from\s+"([^"]+)"', CLI.read_text()):
        if source.startswith((".", "/")):
            continue
        repo, pin = source.rsplit("@", 1)
        if not re.fullmatch(r"[0-9a-f]{40}", pin):
            raise RuntimeError(f"Unpinned dependency: {source}")
        cache = Path.home() / ".goose/pkg/github.com" / repo / pin[:12]
        head = run(["git", "-C", cache, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        if head != pin:
            raise RuntimeError(f"Dependency checkout mismatch: {name}: {head}")
        # Verify consumed tracked bytes against the checkout, then fingerprint all
        # tracked sources/notices; ignored native build products are not sources.
        run(["git", "-C", cache, "diff", "--exit-code", "HEAD"], capture_output=True)
        paths = run(["git", "-C", cache, "ls-files", "-z"], capture_output=True).stdout.split(b"\0")
        hashes = {os.fsdecode(p): sha(cache / os.fsdecode(p)) for p in paths if p}
        result[name] = {"source": source, "commit": head, "source_sha256": hashes}
    return result


def sanitizer_link_check(folder, env):
    """Keep explicit C++ vptr checks when Goose links through a C driver."""
    cpp = folder / "link-check.cpp"
    source = folder / "link-check.c"
    obj = folder / "link-check.o"
    binary = folder / "link-check"
    cpp.write_text('struct Base { virtual int value() { return 7; } };\n'
                   'extern "C" int dispatch(Base *p) { return p->value(); }\n'
                   'extern "C" Base *object() { static Base base; return &base; }\n')
    source.write_text('struct Base;\nextern struct Base *object(void);\n'
                      'extern int dispatch(struct Base *);\n'
                      'int main(void) { return dispatch(object()) != 7; }\n')
    cxx = folder / ("clang++" if (folder / "clang++").exists() else "g++")
    run([cxx, "-fsanitize=vptr", "-c", cpp, "-o", obj], env=env)
    run([folder / "production-cc", source, obj, "-lstdc++", "-o", binary], env=env)
    run([binary], env=dict(env, ASAN_OPTIONS="detect_leaks=1:abort_on_error=1", UBSAN_OPTIONS="halt_on_error=1"))


def build(goose, cc, sanitize, folder):
    compiler = shutil.which(cc)
    if not compiler:
        raise RuntimeError(f"Compiler not found: {cc}")
    compiler = str(Path(compiler).resolve())
    version = run([compiler, "--version"], capture_output=True, text=True).stdout
    clang = "clang" in version.lower()
    cxx_name = "clang++" if clang else "g++"
    cxx = shutil.which(cxx_name)
    if not cxx:
        raise RuntimeError("Matching C++ compiler missing")
    cxx = str(Path(cxx).absolute())
    flags = (["-O1", "-g", "-fno-omit-frame-pointer", "-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
             if sanitize else ["-O2"])
    curl_cflags = shlex.split(run(["pkg-config", "--cflags", "libcurl"], capture_output=True, text=True).stdout)
    curl_libs = shlex.split(run(["pkg-config", "--libs", "libcurl"], capture_output=True, text=True).stdout)
    shim = folder / "transport.o"
    shim_command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-fPIC", *flags, *curl_cflags,
                    "-c", str(HERE / "transport.c"), "-o", str(shim)]
    run(shim_command)
    oracle = folder / "curl-probe"
    oracle_command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", *flags, *curl_cflags,
                      str(HERE / "curl_probe.c"), *curl_libs, *(["-no-pie"] if sanitize else []), "-o", str(oracle)]
    run(oracle_command)
    log = folder / "compiler-commands.jsonl"
    log.write_text("".join(json.dumps(command)+"\n" for command in (shim_command, oracle_command)))
    link_flags = ["-fsanitize=vptr", "-fsanitize-link-c++-runtime", "-lstdc++"] if sanitize and clang else []
    for name, driver, fixture in [("cc", compiler, True), ("production-cc", compiler, False), (cxx_name, cxx, False)]:
        wrapper = folder / name
        per_flags = flags + (["-fsanitize=vptr"] if sanitize and name == cxx_name else [])
        wrapper.write_text("#!/usr/bin/env python3\nimport json,os,sys\n"
            f"compiler={driver!r}\nflags={per_flags!r}\nlog={str(log)!r}\n"
            "args=sys.argv[1:]\n"
            "probe=any(a in args for a in ('-v','--version','-dumpversion','-dumpmachine'))\n"
            "link=not probe and not any(a in args for a in ('-c','-E','-S'))\n"
            "program=link and any(a.startswith('@') and a.endswith(('/link-cc.rsp','/link-cxx.rsp')) for a in args)\n"
            f"extra=[{str(shim)!r},'-Wl,--wrap=curl_multi_add_handle','-lcurl'] if program and {fixture!r} else []\n"
            f"if link: extra.extend({link_flags!r})\n"
            + ("if link: extra.append('-no-pie')\n" if sanitize else "")
            + "effective=[compiler,*args,*([] if probe else flags),*extra]\n"
            "with open(log,'a') as f: f.write(json.dumps(effective)+'\\n')\n"
            "os.execv(compiler,effective)\n")
        wrapper.chmod(0o755)
    env = dict(os.environ, PATH=str(folder) + os.pathsep + os.environ["PATH"])
    if sanitize:
        sanitizer_link_check(folder, env)
    binaries = {"fixture": folder / "artifact-fixture", "production": folder / "artifact-production",
                "policy": folder / "policy-probe", "curl": oracle}
    for name, source in [("fixture", CLI), ("production", CLI), ("policy", CLI.parent / "probe.goose")]:
        wrapper = folder / ("cc" if name == "fixture" else "production-cc")
        run([goose, "build", source, "--standalone", "--cc", wrapper, "-o", binaries[name]], cwd=ROOT, env=env)
    tools = {name: {"path": str(path), "sha256": sha(Path(path)),
                    "version": run([path, "--version"], capture_output=True, text=True).stdout.strip()}
             for name, path in [("goose", goose), ("cc", compiler), ("cxx", cxx)]}
    return binaries, tools, env


def corpus():
    result = []
    def add(raw, host="example.com", port=443, accepted=False):
        result.append((raw, host, port, accepted))
    for tail in ["", "/", "?", "/a%2Fb?q=%40%23%3A", "/a/../b", "/a%00b", "/x?next=https://other.example/"]:
        add("https://example.com" + tail, accepted=True)
    for host in ["localhost", "xn--bcher-kva.example", "a-b.example", "a1", "[::1]", "[2001:db8::1]",
                 "[0:0:0:0:0:0:0:1]", "[::ffff:192.0.2.1]"]:
        add(f"https://{host}/x", host, accepted=True)
    for port in [1, 443, 8443, 65535]:
        add(f"https://example.com:{port}/", port=port, accepted=True)
    for raw in ["", "example.com", "//example.com/a", "http://example.com", "HTTPS://example.com/",
                "https:///example.com", "https://", "https://@example.com", "https://user@example.com",
                "https://user:pass@example.com", "https://example.com#", "https://example.com/#x",
                "https://example.com:", "https://example.com:0443", "https://example.com:0",
                "https://example.com:65536", "https://example.com:444", "https://example.com:443@evil.example/",
                "https://example.com%40evil.example/", "https://example.com%2fevil.example/",
                "https://%65xample.com/", "https://example.com\\@evil.example/", "https://example.com/ bad",
                "https://example.com/%zz", "https://example.com/\n", "https://EXAMPLE.com/",
                "https://example.com./", "https://example..com/", "https://evil.example/",
                "https://example.com.evil/", "https://example.com:443:443/", "https://example.com:443?x#y"]:
        add(raw)
    for host in ["127.0.0.1", "127.1", "2130706433", "0177.0.0.1", "0x7f000001", "example.123",
                 "-a.example", "a-.example", "a_b.example", "a..example", "example.", "[v1.name]",
                 "[fe80::1%25eth0]", "[2001:DB8::1]", "[::g]", "[::1]suffix", "x"*64+".example"]:
        add(f"https://{host}/", host)
    for host, port in [("example.com", 0), ("example.com", -1), ("example.com", 65536), ("", 443),
                       ("EXAMPLE.com", 443), ("example.com.", 443)]:
        add("https://example.com/", host, port)
    add("https://example.com/", "other.example")
    add("https://[::1]/", "[0:0:0:0:0:0:0:1]")
    prefix = "https://example.com/"
    add(prefix + "a"*(8192-len(prefix)), accepted=True)
    add(prefix + "a"*(8193-len(prefix)))
    # Canonical length bounds for DNS names/labels, independent of URL length.
    host253 = ".".join(["a"*63, "b"*63, "c"*63, "d"*61])
    add("https://"+host253+"/", host253, accepted=True)
    host254 = host253+"d"
    add("https://"+host254+"/", host254)
    return result


def policy_checks(binaries, env):
    cases = corpus()
    oracle_lines = run([binaries["curl"], *(x[0] for x in cases)], env=env, capture_output=True, text=True).stdout.splitlines()
    assert len(oracle_lines) == len(cases)
    checked = []
    for (raw, host, port, expected), line in zip(cases, oracle_lines):
        result = run([binaries["policy"], raw, host, str(port)], env=env, capture_output=True, text=True)
        assert result.stderr == "" and result.stdout in ("0\n", "1\n"), (result.stdout, result.stderr)
        accepted = result.stdout == "1\n"
        assert accepted == expected, (raw, host, port, accepted, expected)
        backend = json.loads(line)
        if accepted:
            assert backend["status"] == 0 and backend["scheme"] == "https" and backend["port"] == str(port), (raw, backend)
            if host.startswith("["):
                assert ipaddress.IPv6Address(backend["host"][1:-1]) == ipaddress.IPv6Address(host[1:-1])
            else:
                assert backend["host"] == host, (raw, backend)
        checked.append({"url_sha256": hashlib.sha256(raw.encode()).hexdigest(), "bytes": len(raw.encode()),
                        "trusted_host": host, "trusted_port": port, "accepted": accepted,
                        "curl_authority": backend})
    return checked


def certificate(folder):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
            .not_valid_after(now+datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    ca, private = folder / "ca.pem", folder / "key.pem"
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    return ca, private


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *args):
        pass
    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass  # Expected when a strict TLS client rejects the fixture CA.
    def do_GET(self):
        self.server.requests.append(self.path)
        code = self.server.code
        body = self.server.body
        self.send_response(code)
        if code == 302:
            self.send_header("Location", self.server.redirect)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass


def integration(binaries, env, folder):
    ca, private = certificate(folder)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(ca, private)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.requests = []
    server.body = bytes(range(256))*257
    server.code = 200
    server.redirect = "/redirected"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    signing = ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"goose-url artifact fixture only").digest())
    public = signing.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    base = f"https://localhost:{server.server_port}"
    checked = []
    def case(name, *, tail="/payload", raw_url=None, host="localhost", port=None, stage="None", code=200,
             digest=None, metadata_url=None, corrupt_signature=False, production=False, requests=1, limit=1048576):
        url = raw_url if raw_url is not None else base+tail
        parent = folder / name
        parent.mkdir(mode=0o700)
        sentinel = parent / "sentinel"
        sentinel.write_bytes(b"existing bytes remain")
        raw = json.dumps({"url": metadata_url if metadata_url is not None else url,
                          "sha256": digest if digest is not None else hashlib.sha256(server.body).hexdigest()},
                         separators=(",", ":")).encode()
        metadata = folder / (name+".json")
        metadata.write_bytes(raw)
        sig = signing.sign(raw).hex()
        if corrupt_signature:
            sig = ("00" if sig[:2] != "00" else "01") + sig[2:]
        before = len(server.requests)
        server.code = code
        result = subprocess.run([str(binaries["production" if production else "fixture"]), str(metadata), sig, public,
                                 url, host, str(server.server_port if port is None else port), str(parent),
                                 "staging.part", "final.bin", str(limit)],
                                env=dict(env, GOOSE_URL_FIXTURE_CA=str(ca), GOOSE_URL_FIXTURE_URL=url),
                                capture_output=True, text=True, timeout=30)
        expected_code = 0 if stage == "None" else 1
        assert result.returncode == expected_code, (name, result.returncode, result.stdout, result.stderr)
        text = result.stdout if expected_code == 0 else result.stderr
        assert (result.stderr if expected_code == 0 else result.stdout) == "", (name, result)
        assert text.startswith("artifact: ") and text.endswith("\n") and text.count("\n") == 1, (name, text)
        fields = dict(x.split("=", 1) for x in text.strip()[10:].split())
        assert fields["stage"] == stage, (name, fields)
        if stage != "UrlPolicy":
            assert fields["publication"] == ("Applied" if stage == "None" else "NotAttempted"), (name, fields)
        assert len(server.requests)-before == requests, (name, server.requests[before:])
        assert sentinel.read_bytes() == b"existing bytes remain"
        assert not (parent / "staging.part").exists(), name
        if stage == "None":
            assert (parent / "final.bin").read_bytes() == server.body, name
            assert sorted(p.name for p in parent.iterdir()) == ["final.bin", "sentinel"]
            assert server.requests[-1] == tail, (name, server.requests[-1], tail)
        else:
            assert sorted(p.name for p in parent.iterdir()) == ["sentinel"], name
        checked.append({"name": name, "stage": stage, "returncode": expected_code,
                        "requests": requests, "output": fields})
    try:
        case("success")
        case("escaped-path-query", tail="/a%2Fb%40c?q=%23%3A%2F")
        case("redirect", code=302, stage="HttpStatus")
        case("non200", code=403, stage="HttpStatus")
        case("production-tls-untrusted", production=True, stage="HttpRead", requests=0)
        case("digest-mismatch", digest="00"*32, stage="DigestMismatch")
        case("metadata-url-mismatch", metadata_url=base+"/different", stage="Url", requests=0)
        case("signature-invalid", corrupt_signature=True, stage="Signature", requests=0)
        case("body-cap", limit=1024, stage="HttpRead")
        case("policy-host", host="other.example", stage="UrlPolicy", requests=0)
        case("policy-port", port=443, stage="UrlPolicy", requests=0)
        case("policy-userinfo", raw_url=base.replace("https://", "https://user@"), stage="UrlPolicy", requests=0)
        case("policy-fragment", tail="/payload#x", stage="UrlPolicy", requests=0)
        case("policy-escaped-host", raw_url=base.replace("localhost", "%6cocalhost"), stage="UrlPolicy", requests=0)
        case("policy-numeric-host", raw_url=base.replace("localhost", "127.1"), host="127.1", stage="UrlPolicy", requests=0)
        case("policy-empty-port", raw_url="https://localhost:/payload", stage="UrlPolicy", requests=0)
        case("policy-uppercase", raw_url=base.replace("localhost", "LOCALHOST"), host="LOCALHOST", stage="UrlPolicy", requests=0)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)
        assert not thread.is_alive()
    return checked


def benchmark(goose, folder, env, iterations):
    binary = folder / "policy-bench"
    run([goose, "build", CLI.parent / "bench.goose", "--standalone", "--cc", folder / "production-cc", "-o", binary],
        cwd=ROOT, env=env)
    samples = []
    expected = {}
    for mode in ("parse", "policy"):
        run([binary, mode, str(iterations)], env=env, capture_output=True)
    for number in range(7):
        for mode in (("parse", "policy") if number % 2 == 0 else ("policy", "parse")):
            result = run([binary, mode, str(iterations)], env=env, capture_output=True, text=True)
            assert result.stderr == ""
            sample = json.loads(result.stdout)
            assert sample["seconds"] > 0 and sample["iterations"] == iterations, sample
            assert sample["checksum"] == (iterations if mode == "parse" else iterations // 2), sample
            expected.setdefault(mode, sample["checksum"])
            assert sample["checksum"] == expected[mode], sample
            samples.append({"round": number, "mode": mode, "iterations": iterations, **sample})
    return {"binary_sha256": sha(binary), "samples": samples,
            "scope": "shared-host monotonic elapsed time parse_view baseline vs full caller policy; no network or universal speed claim"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--goose", type=Path, default=ROOT / ".toolchain/goose/build/goose")
    parser.add_argument("--cc", default="gcc")
    parser.add_argument("--sanitize", action="store_true")
    parser.add_argument("--bench", action="store_true")
    parser.add_argument("--iterations", type=int, default=100000)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not 4 <= args.iterations <= 1000000 or args.iterations % 4:
        parser.error("iterations must be 4..1000000 divisible by 4")
    if args.bench and args.sanitize:
        parser.error("benchmark timings require a release build")
    if args.output is None:
        args.output = ROOT / ".build" / ("artifact-" + ("sanitize" if args.sanitize else "release") + "-" + args.cc.replace("/", "_") + ".json")
    # A failed rerun must not leave an earlier pass at the advertised path.
    args.output.unlink(missing_ok=True)
    goose = args.goose.resolve()
    pin = (ROOT / "GOOSE_REVISION").read_text().strip()
    version = run([goose, "--version"], capture_output=True, text=True).stdout
    advertised = re.search(r"\bgoose ([0-9a-f]{7,40})\b", version)
    if advertised is None or not pin.startswith(advertised.group(1)):
        raise RuntimeError("Compiler does not advertise the pinned revision")
    folder = ROOT / ".build" / ("artifact-" + args.cc.replace("/", "_") + ("-sanitize" if args.sanitize else "-release"))
    folder.mkdir(parents=True, exist_ok=True)
    before = sources()
    binaries, tools, env = build(goose, args.cc, args.sanitize, folder)
    env.update(ASAN_OPTIONS="detect_leaks=1:abort_on_error=1", UBSAN_OPTIONS="halt_on_error=1")
    deps_before = dependencies()
    binary_hashes = {name: sha(path) for name, path in binaries.items()}
    policy = policy_checks(binaries, env)
    with tempfile.TemporaryDirectory(prefix="fixture-", dir=folder) as tmp:
        checks = integration(binaries, env, Path(tmp).resolve())
    timing = benchmark(goose, folder, env, args.iterations) if args.bench else None
    assert sources() == before, "Sources changed during validation; discard result"
    assert dependencies() == deps_before, "Dependency bytes changed during validation; discard result"
    assert {name: sha(path) for name, path in binaries.items()} == binary_hashes, "Binary changed"
    for tool in tools.values():
        assert sha(Path(tool["path"])) == tool["sha256"], "Compiler bytes changed"
    report = {"status": "passed", "recorded_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "source_revision": run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip(),
              "source_dirty": bool(run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True).stdout),
              "source_sha256": before, "goose_revision": pin, "tools": tools, "dependencies": deps_before,
              "backends": {name: run(["pkg-config", "--modversion", name], capture_output=True, text=True).stdout.strip()
                           for name in ("libcurl", "libsodium", "simdjson")},
              "sanitize": args.sanitize, "binary_sha256": binary_hashes,
              "compiler_commands": [json.loads(line) for line in (folder / "compiler-commands.jsonl").read_text().splitlines()],
              "compiler_commands_sha256": sha(folder / "compiler-commands.jsonl"), "policy_cases": policy,
              "integration_cases": checks, "benchmark": timing,
              "limits": "Loopback TLS only; CURLU authority agreement for accepted corpus, no DNS-address confinement or path authorization claim"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2)+"\n")
    temporary.replace(args.output)
    print(f"artifact checks: {len(policy)} policy/CURLU cases, {len(checks)} real-consumer cases passed; {args.output}")


if __name__ == "__main__":
    main()
