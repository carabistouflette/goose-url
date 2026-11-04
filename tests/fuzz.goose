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

        let formatted = url::to_string(u1);
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
            let s = url::to_string(u);
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
        let res_str = url::to_string(resolved);
        assert(res_str.len > 0);
        assert(resolved.scheme == "http" || resolved.scheme == "g");
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
                let formatted = url::to_string(u);
                write_stdout("OK ");
                write_stdout(formatted);
                write_stdout("\n");
            }
        } else if line[0] == 'R' && line.len >= 2 && line[1] == ' ' {
            let rest = line[2..];
            // Split by space: base reference
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
                        let res_str = url::to_string(resolved);
                        write_stdout("OK ");
                        write_stdout(res_str);
                        write_stdout("\n");
                    }
                }
            }
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

    write_stdout("all goose-url property tests passed\n");
}
