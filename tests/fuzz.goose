// SPDX-License-Identifier: Apache-2.0
// Property and differential fuzz harness for goose-url.
import std;
import os;
import url from "..";

struct Prng {
    state: u64 = 88172645463325252,
}

fn next_u64(p: Prng&) -> u64 {
    var x = p.state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    p.state = x;
    x
}

fn next_int(p: Prng&, max: i64) -> i64 {
    if max <= 0 { return 0; }
    let val = p.next_u64() % (max as u64);
    val as i64
}

fn random_string(p: Prng&, charset: const u8[:], max_len: i64, out: u8[>..]&) {
    let len = p.next_int(max_len + 1);
    for _ in len {
        let idx = p.next_int(charset.len);
        out.push(charset[idx]);
    }
}

fn select_scheme(idx: i64) -> u8[:] {
    if idx == 0 { return "http"; }
    if idx == 1 { return "https"; }
    if idx == 2 { return "ftp"; }
    if idx == 3 { return "ws"; }
    if idx == 4 { return "wss"; }
    if idx == 5 { return "urn"; }
    return "custom+scheme";
}

fn select_host(idx: i64) -> u8[:] {
    if idx == 0 { return "localhost"; }
    if idx == 1 { return "example.com"; }
    if idx == 2 { return "127.0.0.1"; }
    if idx == 3 { return "sub.domain.org"; }
    return "foo-bar";
}

fn select_path(idx: i64) -> u8[:] {
    if idx == 0 { return ""; }
    if idx == 1 { return "/"; }
    if idx == 2 { return "/a"; }
    if idx == 3 { return "/a/b/c"; }
    if idx == 4 { return "/path/to/resource.html"; }
    return "/index.php";
}

fn select_query(idx: i64) -> u8[:] {
    if idx == 0 { return ""; }
    if idx == 1 { return "k=v"; }
    if idx == 2 { return "a=1&b=2"; }
    if idx == 3 { return "search=foo+bar&lang=en"; }
    return "flag";
}

fn select_frag(idx: i64) -> u8[:] {
    if idx == 0 { return ""; }
    if idx == 1 { return "top"; }
    if idx == 2 { return "section-1"; }
    return "anchor";
}

fn select_ref(idx: i64) -> u8[:] {
    if idx == 0 { return "g:h"; }
    if idx == 1 { return "g"; }
    if idx == 2 { return "./g"; }
    if idx == 3 { return "g/"; }
    if idx == 4 { return "/g"; }
    if idx == 5 { return "//g"; }
    if idx == 6 { return "?y"; }
    if idx == 7 { return "g?y"; }
    if idx == 8 { return "#s"; }
    if idx == 9 { return "g#s"; }
    if idx == 10 { return "g?y#s"; }
    if idx == 11 { return ";x"; }
    if idx == 12 { return "g;x"; }
    if idx == 13 { return "g;x?y#s"; }
    if idx == 14 { return ""; }
    if idx == 15 { return "."; }
    if idx == 16 { return "./"; }
    if idx == 17 { return ".."; }
    if idx == 18 { return "../"; }
    if idx == 19 { return "../g"; }
    if idx == 20 { return "../.."; }
    if idx == 21 { return "../../"; }
    return "../../g";
}

fn test_roundtrip_properties(p: Prng&, iterations: i64) {
    for _ in iterations {
        let scheme = select_scheme(p.next_int(7));
        let host = select_host(p.next_int(5));
        let port_choice = p.next_int(3);
        var port_str = "";
        if port_choice == 1 {
            port_str = ":8080";
        } else if port_choice == 2 {
            port_str = ":443";
        }
        let path = select_path(p.next_int(6));
        let q = select_query(p.next_int(5));
        let f = select_frag(p.next_int(4));

        var raw: u8[>..] = [];
        raw.append(scheme);
        raw.append("://");
        raw.append(host);
        raw.append(port_str);
        raw.append(path);
        if q.len > 0 {
            raw.push('?');
            raw.append(q);
        }
        if f.len > 0 {
            raw.push('#');
            raw.append(f);
        }

        let u1, err1 = url::parse(raw);
        assert(err1.kind == url::ErrorKind.None);

        let formatted = checked_string(u1);
        let u2, err2 = url::parse(formatted);
        assert(err2.kind == url::ErrorKind.None);

        assert(u1.scheme == u2.scheme);
        assert(u1.host == u2.host);
        assert(u1.port == u2.port);
        assert(u1.path == u2.path);
        assert(u1.query == u2.query);
        assert(u1.fragment == u2.fragment);
    }
}

fn test_random_junk_robustness(p: Prng&, iterations: i64) {
    let charset: const u8[:] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~:/?#[]@!$&'()*+,;=% \t\r\n\x00\xff";
    for _ in iterations {
        var junk: u8[>..] = [];
        p.random_string(charset, 120, junk);
        // parse must either succeed or return a structured error, NEVER panic/crash.
        let u, err = url::parse(junk);
        if err.kind == url::ErrorKind.None {
            let s = checked_string(u);
            assert(s.len <= url::MAX_URL_BYTES);
        } else {
            assert(err.offset >= 0);
        }
    }
}

fn test_resolution_invariants(p: Prng&, iterations: i64) {
    let base_str = "http://a/b/c/d;p?q";
    let base, b_err = url::parse(base_str);
    assert(b_err.kind == url::ErrorKind.None);

    for _ in iterations {
        let r = select_ref(p.next_int(23));
        let resolved, r_err = url::resolve(base, r);
        assert(r_err.kind == url::ErrorKind.None);
        let res_str = checked_string(resolved);
        assert(res_str.len > 0);
        assert(resolved.scheme == "http" || resolved.scheme == "g");
    }
}

fn test_modifier_invariants(p: Prng&, iterations: i64) {
    let base_url_str = "http://example.com:8080/path/to/resource?foo=bar#section";
    let u, err = url::parse(base_url_str);
    assert(err.kind == url::ErrorKind.None);

    for _ in iterations {
        // with_scheme
        let u_scheme, s_ok = url::with_scheme(u, "https");
        assert(s_ok);
        assert(u_scheme.scheme == "https");
        assert(u_scheme.host == u.host);
        assert(u_scheme.port == u.port);
        assert(u_scheme.path == u.path);
        assert(u_scheme.query == u.query);
        assert(u_scheme.fragment == u.fragment);

        // with_host
        let u_host, h_ok = url::with_host(u, "newhost.org");
        assert(h_ok);
        assert(u_host.host == "newhost.org");
        assert(u_host.scheme == u.scheme);
        assert(u_host.port == u.port);
        assert(u_host.path == u.path);
        assert(u_host.query == u.query);
        assert(u_host.fragment == u.fragment);

        // with_port
        let u_port, p_ok = url::with_port(u, 9000);
        assert(p_ok);
        assert(u_port.port == 9000);
        assert(u_port.scheme == u.scheme);
        assert(u_port.host == u.host);
        assert(u_port.path == u.path);
        assert(u_port.query == u.query);
        assert(u_port.fragment == u.fragment);

        // with_path
        let u_path, u_path_ok = url::with_path(u, "/a/b/../c"); assert(u_path_ok);
        assert(u_path.path == "/a/c");
        assert(u_path.scheme == u.scheme);
        assert(u_path.host == u.host);
        assert(u_path.port == u.port);
        assert(u_path.query == u.query);
        assert(u_path.fragment == u.fragment);

        // with_query
        let u_query, u_query_ok = url::with_query(u, "new=true"); assert(u_query_ok);
        assert(u_query.query == "new=true");
        assert(u_query.has_query);
        assert(u_query.scheme == u.scheme);
        assert(u_query.host == u.host);
        assert(u_query.port == u.port);
        assert(u_query.path == u.path);
        assert(u_query.fragment == u.fragment);

        // with_fragment
        let u_frag, u_frag_ok = url::with_fragment(u, "newtop"); assert(u_frag_ok);
        assert(u_frag.fragment == "newtop");
        assert(u_frag.has_fragment);
        assert(u_frag.scheme == u.scheme);
        assert(u_frag.host == u.host);
        assert(u_frag.port == u.port);
        assert(u_frag.path == u.path);
        assert(u_frag.query == u.query);
    }
}

fn test_query_param_invariants(p: Prng&, iterations: i64) {
    let charset: const u8[:] = "abcdefghijklmnopqrstuvwxyz0123456789";

    for _ in iterations {
        var params: url::QueryParam[>..] = [];
        let num_pairs = p.next_int(5) + 1;

        for _ in num_pairs {
            var k: u8[>..] = [];
            p.random_string(charset, 5, k);
            if k.len == 0 { k.push('k'); }

            var v: u8[>..] = [];
            p.random_string(charset, 5, v);

            url::query_set(params, k, v);
            assert(url::query_has(params, k));

            var retrieved: u8[>..] = [];
            assert(url::query_get(params, k, retrieved));
            assert(retrieved == v);
        }

        url::query_sort(params);
        if params.len > 1 {
            var prev_key: u8[>..] = [];
            for param, idx in params {
                if idx > 0 {
                    assert(url::bytes_compare(prev_key, param.key) <= 0);
                }
                prev_key.clear();
                prev_key.append(param.key);
            }
        }
    }
}

fn run_stdin_mode() {
    var line: u8[>..] = [];
    while read_line(line) {
        if line.len == 0 {
            line.clear();
            continue;
        }

        if line[0] == 'P' && line.len >= 2 && line[1] == ' ' {
            let target = line[2..];
            let u, err = url::parse(target);
            if err.kind != url::ErrorKind.None {
                write_stdout("ERR\n");
            } else {
                let formatted = checked_string(u);
                write_stdout("OK ");
                write_stdout(formatted);
                write_stdout("\n");
            }
        } else if line[0] == 'R' && line.len >= 2 && line[1] == ' ' {
            let rest = line[2..];
            var sep = -1;
            for c, idx in rest {
                if c == ' ' {
                    sep = idx;
                    break;
                }
            }
            if sep < 0 {
                write_stdout("ERR\n");
            } else {
                let base_str = rest[..sep];
                let ref_str = rest[sep + 1..];
                let base, b_err = url::parse(base_str);
                if b_err.kind != url::ErrorKind.None {
                    write_stdout("ERR\n");
                } else {
                    let resolved, r_err = url::resolve(base, ref_str);
                    if r_err.kind != url::ErrorKind.None {
                        write_stdout("ERR\n");
                    } else {
                        let res_str = checked_string(resolved);
                        write_stdout("OK ");
                        write_stdout(res_str);
                        write_stdout("\n");
                    }
                }
            }
        } else if line[0] == 'Q' && line.len >= 2 && line[1] == ' ' {
            let target = line[2..];
            let params, query_error = url::parse_query(target);
            var formatted: u8[>..] = [];
            if query_error.kind != url::ErrorKind.None || !url::format_query(params, formatted) { write_stdout("ERR\n"); }
            else { write_stdout("OK "); write_stdout(formatted); write_stdout("\n"); }
        } else {
            write_stdout("ERR UNKNOWN_CMD\n");
        }

        line.clear();
    }
}

fn main() {
    let argv = args();
    if argv.len > 1 && argv[1] == "--stdin" {
        run_stdin_mode();
        return;
    }

    var p = Prng {};
    test_roundtrip_properties(p, 1000);
    test_random_junk_robustness(p, 2000);
    test_resolution_invariants(p, 500);
    test_modifier_invariants(p, 500);
    test_query_param_invariants(p, 500);

    write_stdout("all goose-url property tests passed\n");
}

fn checked_string(u: url::Url&) -> u8[>..] { let out, error = url::to_string(u); assert(error.kind == url::ErrorKind.None); return out; }
fn checked_query(input: const u8[:]) -> url::QueryParam[>..] { let params, error = url::parse_query(input); assert(error.kind == url::ErrorKind.None); return params; }
