// SPDX-License-Identifier: Apache-2.0
// Comprehensive unit tests for goose-url.
import std;
import url from "..";

fn test_basic_parsing() {
    let u, err = url::parse("https://user:pass@example.com:8443/api/v1/resource?filter=active&sort=desc#section-1");
    assert(err.kind == url::ErrorKind.None);
    assert(u.scheme == "https");
    assert(u.has_authority);
    assert(u.userinfo == "user:pass");
    assert(u.host == "example.com");
    assert(u.port == 8443);
    assert(u.path == "/api/v1/resource");
    assert(u.has_query);
    assert(u.query == "filter=active&sort=desc");
    assert(u.has_fragment);
    assert(u.fragment == "section-1");

    let reconstructed = checked_string(u);
    assert(reconstructed == "https://user:pass@example.com:8443/api/v1/resource?filter=active&sort=desc#section-1");
}

fn test_ipv6_host() {
    let u, err = url::parse("http://[2001:db8::1]:8080/test");
    assert(err.kind == url::ErrorKind.None);
    assert(u.scheme == "http");
    assert(u.has_authority);
    assert(u.userinfo.len == 0);
    assert(u.host == "[2001:db8::1]");
    assert(u.port == 8080);
    assert(u.path == "/test");

    let reconstructed = checked_string(u);
    assert(reconstructed == "http://[2001:db8::1]:8080/test");
}

fn test_file_url() {
    let u, err = url::parse("file:///etc/passwd");
    assert(err.kind == url::ErrorKind.None);
    assert(u.scheme == "file");
    assert(u.has_authority);
    assert(u.host.len == 0);
    assert(u.port == -1);
    assert(u.path == "/etc/passwd");
    assert(!u.has_query);
    assert(!u.has_fragment);

    let reconstructed = checked_string(u);
    assert(reconstructed == "file:///etc/passwd");
}

fn test_urn_url() {
    let u, err = url::parse("urn:isbn:0451450523");
    assert(err.kind == url::ErrorKind.None);
    assert(u.scheme == "urn");
    assert(!u.has_authority);
    assert(u.path == "isbn:0451450523");
    assert(!u.has_query);
    assert(!u.has_fragment);

    let reconstructed = checked_string(u);
    assert(reconstructed == "urn:isbn:0451450523");
}

fn test_relative_reference() {
    let u, err = url::parse("/path/to/page?q=1#frag");
    assert(err.kind == url::ErrorKind.None);
    assert(u.scheme.len == 0);
    assert(!u.has_authority);
    assert(u.path == "/path/to/page");
    assert(u.has_query);
    assert(u.query == "q=1");
    assert(u.has_fragment);
    assert(u.fragment == "frag");

    let reconstructed = checked_string(u);
    assert(reconstructed == "/path/to/page?q=1#frag");
}

fn test_remove_dot_segments() {
    var out: u8[>..] = [];
    url::remove_dot_segments("/a/b/c/./../../g", out);
    assert(out == "/a/g");

    out.clear();
    url::remove_dot_segments("mid/content/5/../6", out);
    assert(out == "mid/content/6");

    out.clear();
    url::remove_dot_segments("/.", out);
    assert(out == "/");

    out.clear();
    url::remove_dot_segments("/..", out);
    assert(out == "/");

    out.clear();
    url::remove_dot_segments(".", out);
    assert(out.len == 0);

    out.clear();
    url::remove_dot_segments("..", out);
    assert(out.len == 0);
}

fn check_resolve(base: url::Url&, rel: const u8[:], expected: const u8[:]) {
    let res, err = url::resolve(base, rel);
    assert(err.kind == url::ErrorKind.None);
    let s = checked_string(res);
    assert(s == expected);
}

// RFC 3986 Section 5.4.1 Normal Examples
fn test_rfc_3986_normal() {
    let base, err = url::parse("http://a/b/c/d;p?q");
    assert(err.kind == url::ErrorKind.None);

    check_resolve(base, "g:h", "g:h");
    check_resolve(base, "g", "http://a/b/c/g");
    check_resolve(base, "./g", "http://a/b/c/g");
    check_resolve(base, "g/", "http://a/b/c/g/");
    check_resolve(base, "/g", "http://a/g");
    check_resolve(base, "//g", "http://g");
    check_resolve(base, "?y", "http://a/b/c/d;p?y");
    check_resolve(base, "g?y", "http://a/b/c/g?y");
    check_resolve(base, "#s", "http://a/b/c/d;p?q#s");
    check_resolve(base, "g#s", "http://a/b/c/g#s");
    check_resolve(base, "g?y#s", "http://a/b/c/g?y#s");
    check_resolve(base, ";x", "http://a/b/c/;x");
    check_resolve(base, "g;x", "http://a/b/c/g;x");
    check_resolve(base, "g;x?y#s", "http://a/b/c/g;x?y#s");
    check_resolve(base, "", "http://a/b/c/d;p?q");
    check_resolve(base, ".", "http://a/b/c/");
    check_resolve(base, "./", "http://a/b/c/");
    check_resolve(base, "..", "http://a/b/");
    check_resolve(base, "../", "http://a/b/");
    check_resolve(base, "../g", "http://a/b/g");
    check_resolve(base, "../..", "http://a/");
    check_resolve(base, "../../", "http://a/");
    check_resolve(base, "../../g", "http://a/g");
}

// RFC 3986 Section 5.4.2 Abnormal Examples
fn test_rfc_3986_abnormal() {
    let base, err = url::parse("http://a/b/c/d;p?q");
    assert(err.kind == url::ErrorKind.None);

    check_resolve(base, "../../../g", "http://a/g");
    check_resolve(base, "../../../../g", "http://a/g");
    check_resolve(base, "/./g", "http://a/g");
    check_resolve(base, "/../g", "http://a/g");
    check_resolve(base, "g.", "http://a/b/c/g.");
    check_resolve(base, ".g", "http://a/b/c/.g");
    check_resolve(base, "g..", "http://a/b/c/g..");
    check_resolve(base, "..g", "http://a/b/c/..g");
    check_resolve(base, "./../g", "http://a/b/g");
    check_resolve(base, "./g/.", "http://a/b/c/g/");
    check_resolve(base, "g/./h", "http://a/b/c/g/h");
    check_resolve(base, "g/../h", "http://a/b/c/h");
    check_resolve(base, "g;x=1/./y", "http://a/b/c/g;x=1/y");
    check_resolve(base, "g;x=1/../y", "http://a/b/c/y");
    check_resolve(base, "g?y/./x", "http://a/b/c/g?y/./x");
    check_resolve(base, "g?y/../x", "http://a/b/c/g?y/../x");
    check_resolve(base, "g#s/./x", "http://a/b/c/g#s/./x");
    check_resolve(base, "g#s/../x", "http://a/b/c/g#s/../x");
}

fn test_percent_codec() {
    var encoded: u8[>..] = [];
    url::percent_encode("Hello World! / 100% test", encoded);
    assert(encoded == "Hello%20World%21%20%2F%20100%25%20test");

    var decoded: u8[>..] = [];
    let ok = url::percent_decode(encoded, decoded);
    assert(ok);
    assert(decoded == "Hello World! / 100% test");

    // Invalid percent encoding checks
    var bad: u8[>..] = [];
    assert(!url::percent_decode("%", bad));
    assert(!url::percent_decode("%2", bad));
    assert(!url::percent_decode("%2G", bad));
    assert(!url::percent_decode("%G2", bad));
}

fn test_query_codec() {
    let params = checked_query("key=hello+world&empty=&flag&special=%26%3D%25");
    assert(params.len == 4);
    for p, i in params {
        if i == 0 { assert(p.key == "key" && p.value == "hello world"); }
        if i == 1 { assert(p.key == "empty" && p.value == ""); }
        if i == 2 { assert(p.key == "flag" && p.value == ""); }
        if i == 3 { assert(p.key == "special" && p.value == "&=%"); }
    }

    var formatted: u8[>..] = [];
    url::format_query(params, formatted);
    assert(formatted == "key=hello+world&empty=&flag=&special=%26%3D%25");
}

fn test_error_cases() {
    let u_empty, err_empty = url::parse("");
    assert(err_empty.kind == url::ErrorKind.None);
    assert(u_empty.scheme.len == 0 && u_empty.path.len == 0);

    let _, err_bad_scheme = url::parse("1http://example.com");
    assert(err_bad_scheme.kind == url::ErrorKind.InvalidScheme);

    let _, err_bad_port = url::parse("http://example.com:abc/");
    assert(err_bad_port.kind == url::ErrorKind.InvalidPort);

    let _, err_port_overflow = url::parse("http://example.com:70000/");
    assert(err_port_overflow.kind == url::ErrorKind.InvalidPort);

    let _, err_unclosed_ipv6 = url::parse("http://[::1/path");
    assert(err_unclosed_ipv6.kind == url::ErrorKind.InvalidHost);

    let _, err_empty_ipv6 = url::parse("http://[]/");
    assert(err_empty_ipv6.kind == url::ErrorKind.InvalidHost);

    let _, err_bad_ipv6_char = url::parse("http://[xyz]/");
    assert(err_bad_ipv6_char.kind == url::ErrorKind.InvalidHost);

    let _, err_bad_ipv6_no_colon = url::parse("http://[1234]/");
    assert(err_bad_ipv6_no_colon.kind == url::ErrorKind.InvalidHost);
}

fn test_url_view() {
    let raw = "https://user:pass@example.com:8443/api/v1/resource?filter=active#sec-1";
    let v, err = url::parse_view(raw);
    assert(err.kind == url::ErrorKind.None);
    assert(v.scheme == "https");
    assert(v.has_authority);
    assert(v.userinfo == "user:pass");
    assert(v.host == "example.com");
    assert(v.port == 8443);
    assert(v.path == "/api/v1/resource");
    assert(v.has_query);
    assert(v.query == "filter=active");
    assert(v.has_fragment);
    assert(v.fragment == "sec-1");
}

fn test_query_manipulation() {
    var params = checked_query("b=2&a=1&c=3&a=duplicate");
    assert(url::query_has(params, "a"));
    assert(!url::query_has(params, "nonexistent"));

    var val: u8[>..] = [];
    assert(url::query_get(params, "b", val));
    assert(val == "2");

    // set_param: updates first, drops subsequent duplicate 'a'
    url::query_set(params, "a", "10");
    val.clear();
    assert(url::query_get(params, "a", val));
    assert(val == "10");
    assert(params.len == 3); // b=2, a=10, c=3

    // append_param
    url::query_append(params, "d", "4");
    assert(params.len == 4);

    // delete_param
    url::query_delete(params, "c");
    assert(!url::query_has(params, "c"));
    assert(params.len == 3); // b=2, a=10, d=4

    // sort_params: should sort keys lexicographically -> a, b, d
    url::query_sort(params);
    var formatted: u8[>..] = [];
    url::format_query(params, formatted);
    assert(formatted == "a=10&b=2&d=4");
}

fn test_whatwg_origin() {
    let u1, _ = url::parse("http://example.com/some/path");
    assert(url::origin_string(u1) == "http://example.com");

    let u2, _ = url::parse("http://example.com:80/some/path");
    assert(url::origin_string(u2) == "http://example.com"); // default 80 omitted

    let u3, _ = url::parse("http://example.com:8080/some/path");
    assert(url::origin_string(u3) == "http://example.com:8080");

    let u4, _ = url::parse("https://example.com:443/secure");
    assert(url::origin_string(u4) == "https://example.com"); // default 443 omitted

    let u5, _ = url::parse("https://example.com:8443/secure");
    assert(url::origin_string(u5) == "https://example.com:8443");

    let u6, _ = url::parse("file:///etc/hosts");
    assert(url::origin_string(u6) == "null"); // opaque origin

    let u7, _ = url::parse("urn:isbn:0451450523");
    assert(url::origin_string(u7) == "null"); // opaque origin
}

fn test_component_mutators() {
    let u, _ = url::parse("http://example.com:8080/v1/old?foo=bar#oldfrag");

    let u_scheme, ok1 = url::with_scheme(u, "https");
    assert(ok1);
    let _, bad_scheme_ok = url::with_scheme(u, "1bad");
    assert(!bad_scheme_ok);

    let u_host, ok2 = url::with_host(u_scheme, "api.newdomain.org");
    assert(ok2);
    let _, bad_host_ok = url::with_host(u_scheme, "[invalid_ipv6]");
    assert(!bad_host_ok);

    let u_port, ok3 = url::with_port(u_host, 9443);
    assert(ok3);
    let _, bad_port_ok = url::with_port(u_host, 70000);
    assert(!bad_port_ok);

    let u_path, u_path_ok = url::with_path(u_port, "/v2/../v3/endpoint"); assert(u_path_ok);
    assert(u_path.path == "/v3/endpoint"); // dot segment normalized

    let u_query, u_query_ok = url::with_query(u_path, "new=true&limit=10"); assert(u_query_ok);
    let u_final, u_final_ok = url::with_fragment(u_query, "newfrag"); assert(u_final_ok);

    let s = checked_string(u_final);
    assert(s == "https://api.newdomain.org:9443/v3/endpoint?new=true&limit=10#newfrag");
}

fn main() {
    test_publication_regressions();
    test_basic_parsing();
    test_url_view();
    test_ipv6_host();
    test_file_url();
    test_urn_url();
    test_relative_reference();
    test_remove_dot_segments();
    test_rfc_3986_normal();
    test_rfc_3986_abnormal();
    test_percent_codec();
    test_query_codec();
    test_query_manipulation();
    test_whatwg_origin();
    test_component_mutators();
    test_error_cases();
    print("all goose-url unit tests passed");
}

fn checked_string(u: url::Url&) -> u8[>..] { let out, error = url::to_string(u); assert(error.kind == url::ErrorKind.None); return out; }
fn checked_query(input: const u8[:]) -> url::QueryParam[>..] { let params, error = url::parse_query(input); assert(error.kind == url::ErrorKind.None); return params; }

fn reject_uri(input: const u8[:]) {
    let view, view_error = url::parse_view(input);
    let owned, error = url::parse(input);
    assert(view_error.kind != url::ErrorKind.None && error.kind == view_error.kind);
    assert(owned.scheme.len == 0 && owned.host.len == 0 && owned.path.len == 0);
    assert(error.offset >= 0 && error.offset <= input.len);
}
fn test_publication_regressions() {
    for input in ["http://good.com@evil.com@host/", "http://user name@host/", "http://exa mple/", "http://h/space here", "http://h/\\x", "http://h/\x00", "http://h/\xff", "http://h/%", "http://h/%2g", "http://h/?x=%z0", "http://h/?x=\t", "http://h/#x#y", ":relative", "1bad:x", "http://h]", "http://[:::]/", "http://[1:2:3]/", "http://[1::2::3]/", "http://[12345::]/", "http://[::ffff:192.00.2.1]/", "http://[v.abc]/", "http://[v1.]/", "http://[fe80::1%25eth0]/", "http://h:65536/"] { reject_uri(input); }
    for input in ["http://[::]/", "http://[::1]/", "http://[1:2:3:4:5:6:7:8]/", "http://[::ffff:192.0.2.1]/", "http://[1:2:3:4:5:6:192.0.2.1]/", "http://[v1.a:b]/", "http://[VA.!$&'()*+,;=]/", "http://user%40name@exa%6Dple.com/a%2Fb?x=%23#%20"] {
        let value, error = url::parse(input); assert(error.kind == url::ErrorKind.None);
        let text = checked_string(value); let reparsed, reparsed_error = url::parse(text);
        assert(reparsed_error.kind == url::ErrorKind.None && checked_string(reparsed) == text);
    }
    for input in ["http://@example.com:/", "//@", "//host:", "?", "#", "?#"] {
        let value, error = url::parse(input); assert(error.kind == url::ErrorKind.None); assert(checked_string(value) == input);
    }
    let original, original_error = url::parse("http://a/"); assert(original_error.kind == url::ErrorKind.None);
    for path in ["b", "/p?q", "/p#f", "/%ZZ", "/bad%ZZ/../safe", "/bad space/../safe", "/a?x/../safe", "b/../c"] {
        let value, ok = url::with_path(original, path); assert(!ok && checked_string(value) == "http://a/");
    }
    for host in ["other.test/path", "user@other", "h:80", "[:::]", "host\x00"] {
        let value, ok = url::with_host(original, host); assert(!ok && checked_string(value) == "http://a/");
    }
    let query_value, query_ok = url::with_query(original, "x#y"); assert(!query_ok && checked_string(query_value) == "http://a/");
    let fragment_value, fragment_ok = url::with_fragment(original, "x#y"); assert(!fragment_ok && checked_string(fragment_value) == "http://a/");
    for input in ["role=admin%ZZ&other=1", "%", "a=%2", "a=b&c=%g0"] {
        let params, error = url::parse_query(input); assert(error.kind == url::ErrorKind.InvalidPercentEncoding && params.len == 0);
    }
    var query: u8[>..] = [];
    for i in url::MAX_QUERY_PARAMS { if i > 0 { query.push('&'); } query.append("a=1"); }
    var params, query_error = url::parse_query(query); assert(query_error.kind == url::ErrorKind.None && params.len == url::MAX_QUERY_PARAMS);
    assert(!url::query_append(params, "extra", "x") && params.len == url::MAX_QUERY_PARAMS);
    assert(!url::query_set(params, "extra", "x") && params.len == url::MAX_QUERY_PARAMS);
    query.append("&extra=x");
    let too_many, limit_error = url::parse_query(query); assert(limit_error.kind == url::ErrorKind.TooLong && too_many.len == 0);
    assert(url::query_set(params, "a", "updated") && params.len == 1);
    var binary: u8[>..] = str("keep"); assert(!url::percent_decode("ok%Q0", binary) && binary == "keep");
    var normalized = str("prefix"); assert(url::remove_dot_segments("/a/../b", normalized) && normalized == "prefix/b");
    var raw: u8[>..] = []; raw.resize(21846, '!'); assert(!url::percent_encode(raw, binary) && binary == "keep");
    binary.clear(); assert(url::percent_encode("\x00\xff", binary) && binary == "%00%FF");
    var decoded: u8[>..] = []; assert(url::percent_decode(binary, decoded) && decoded == "\x00\xff");
    var ordered = checked_query("b=1&a=x&a=y"); assert(url::query_sort(ordered));
    var formatted: u8[>..]              = []; assert(url::format_query(ordered, formatted) && formatted == "a=x&a=y&b=1");
    var bytes:     url::QueryParam[>..] = [];
    assert(url::query_append(bytes, "😀", "astral") && url::query_append(bytes, "\xee\x80\x80", "bmp") && url::query_sort(bytes));
    for item, i in bytes { if i == 0 { assert(item.value == "bmp"); } }
    var maximum = str("http://a/"); maximum.resize(url::MAX_URL_BYTES - 1, 'x'); maximum.push('/');
    let large, large_error = url::parse(maximum); assert(large_error.kind == url::ErrorKind.None && checked_string(large).len == url::MAX_URL_BYTES);
    var prefix = str("keep"); assert(url::format(large, prefix).kind == url::ErrorKind.TooLong && prefix == "keep");
    let oversized, oversized_error = url::resolve(large, "child"); assert(oversized_error.kind == url::ErrorKind.TooLong && oversized.path.len == 0);
    let shortened, shortened_error = url::resolve(large, "../../g"); assert(shortened_error.kind == url::ErrorKind.None && checked_string(shortened) == "http://a/g");
    let large_modified, large_ok = url::with_query(large, "x"); assert(!large_ok && checked_string(large_modified).len == url::MAX_URL_BYTES);
    maximum.push('x'); reject_uri(maximum);
}
