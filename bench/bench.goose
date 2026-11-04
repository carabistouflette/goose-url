// SPDX-License-Identifier: Apache-2.0
// High-performance microbenchmark suite for goose-url.
import std;
import os;
import url from "..";

fn parse_iterations(s: const u8[:]) -> i64 {
    var n: i64 = 0;
    for c in s {
        if c < '0' || c > '9' { return -1; }
        n = n * 10 + (c - '0');
    }
    n
}

fn bench_parse(iterations: i64) {
    let target = "https://user:pass@example.com:8443/api/v1/resource/items?filter=active&sort=desc#section-1";
    let start = clock();
    var checksum: i64 = 0;
    for _ in iterations {
        let u, err = url::parse(target);
        if err.kind == url::ErrorKind.None {
            checksum += u.port + u.path.len;
        }
    }
    let elapsed = clock() - start;
    let ops_per_sec = iterations / elapsed;
    let ns_per_op = (elapsed / iterations) * 1000000000.0;

    print("bench_parse:      ", iterations, " ops in ", elapsed, " s (", ops_per_sec as i64, " ops/sec, ", ns_per_op as i64, " ns/op, checksum=", checksum, ")");
}

fn bench_parse_view(iterations: i64) {
    let target = "https://user:pass@example.com:8443/api/v1/resource/items?filter=active&sort=desc#section-1";
    let start = clock();
    var checksum: i64 = 0;
    for _ in iterations {
        let v, err = url::parse_view(target);
        if err.kind == url::ErrorKind.None {
            checksum += v.port + v.path.len;
        }
    }
    let elapsed = clock() - start;
    let ops_per_sec = iterations / elapsed;
    let ns_per_op = (elapsed / iterations) * 1000000000.0;

    print("bench_parse_view: ", iterations, " ops in ", elapsed, " s (", ops_per_sec as i64, " ops/sec, ", ns_per_op as i64, " ns/op, checksum=", checksum, ")");
}

fn bench_resolve(iterations: i64) {
    let base_str = "http://a/b/c/d;p?q";
    let base, b_err = url::parse(base_str);
    assert(b_err.kind == url::ErrorKind.None);
    let ref_str = "../../g?y#s";

    let start = clock();
    var checksum: i64 = 0;
    for _ in iterations {
        let res, r_err = url::resolve(base, ref_str);
        if r_err.kind == url::ErrorKind.None {
            checksum += res.path.len;
        }
    }
    let elapsed = clock() - start;
    let ops_per_sec = iterations / elapsed;
    let ns_per_op = (elapsed / iterations) * 1000000000.0;

    print("bench_resolve:    ", iterations, " ops in ", elapsed, " s (", ops_per_sec as i64, " ops/sec, ", ns_per_op as i64, " ns/op, checksum=", checksum, ")");
}

fn bench_dot_segments(iterations: i64) {
    let path = "/a/b/c/./../../g/../h/./i";
    var out: u8[>..] = [];

    let start = clock();
    var checksum: i64 = 0;
    for _ in iterations {
        out.clear();
        url::remove_dot_segments(path, out);
        checksum += out.len;
    }
    let elapsed = clock() - start;
    let ops_per_sec = iterations / elapsed;
    let ns_per_op = (elapsed / iterations) * 1000000000.0;

    print("bench_dot_remove: ", iterations, " ops in ", elapsed, " s (", ops_per_sec as i64, " ops/sec, ", ns_per_op as i64, " ns/op, checksum=", checksum, ")");
}

fn bench_query_parse(iterations: i64) {
    let q = "search=goose+language&sort=date&order=desc&page=2&limit=50&active=true";

    let start = clock();
    var checksum: i64 = 0;
    for _ in iterations {
        let params = url::parse_query(q);
        checksum += params.len;
    }
    let elapsed = clock() - start;
    let ops_per_sec = iterations / elapsed;
    let ns_per_op = (elapsed / iterations) * 1000000000.0;

    print("bench_query_parse:", iterations, " ops in ", elapsed, " s (", ops_per_sec as i64, " ops/sec, ", ns_per_op as i64, " ns/op, checksum=", checksum, ")");
}

fn bench_origin(iterations: i64) {
    let u, _ = url::parse("https://user:pass@example.com:8443/api/v1/items?k=v#sec");
    var out: u8[>..] = [];

    let start = clock();
    var checksum: i64 = 0;
    for _ in iterations {
        out.clear();
        url::origin(u, out);
        checksum += out.len;
    }
    let elapsed = clock() - start;
    let ops_per_sec = iterations / elapsed;
    let ns_per_op = (elapsed / iterations) * 1000000000.0;

    print("bench_origin:     ", iterations, " ops in ", elapsed, " s (", ops_per_sec as i64, " ops/sec, ", ns_per_op as i64, " ns/op, checksum=", checksum, ")");
}

fn bench_query_sort(iterations: i64) {
    let q = "z=10&a=1&m=5&b=2&k=3&f=6";
    let base_params = url::parse_query(q);

    let start = clock();
    var checksum: i64 = 0;
    for _ in iterations {
        var params: url::QueryParam[>..] = [];
        for p in base_params {
            url::query_append(params, p.key, p.value);
        }
        url::query_sort(params);
        checksum += params.len;
    }
    let elapsed = clock() - start;
    let ops_per_sec = iterations / elapsed;
    let ns_per_op = (elapsed / iterations) * 1000000000.0;

    print("bench_query_sort: ", iterations, " ops in ", elapsed, " s (", ops_per_sec as i64, " ops/sec, ", ns_per_op as i64, " ns/op, checksum=", checksum, ")");
}

fn main() {
    let argv = args();
    var iterations: i64 = 100000;
    if argv.len > 1 {
        let parsed = parse_iterations(argv[1]);
        if parsed > 0 { iterations = parsed; }
    }

    print("=== goose-url microbenchmark (iterations=", iterations, ") ===");
    bench_parse(iterations);
    bench_parse_view(iterations);
    bench_resolve(iterations);
    bench_dot_segments(iterations);
    bench_query_parse(iterations);
    bench_origin(iterations);
    bench_query_sort(iterations);
}
