// SPDX-License-Identifier: Apache-2.0
// Pure Goose implementation of RFC 3986 Uniform Resource Identifiers.
namespace url;
import std;

const MAX_URL_BYTES = 65536;
const MAX_QUERY_PARAMS = 1024;

enum ErrorKind {
    None,
    TooLong,
    EmptyInput,
    InvalidScheme,
    InvalidAuthority,
    InvalidUserinfo,
    InvalidHost,
    InvalidPort,
    InvalidPath,
    InvalidQuery,
    InvalidFragment,
    InvalidPercentEncoding,
}

struct Error {
    kind:   ErrorKind = ErrorKind.None,
    offset: i64       = 0,
}

// Owned URI representation with growable buffers.
struct Url {
    scheme:        u8[] = [],
    has_authority: bool = false,
    userinfo:      u8[] = [],
    host:          u8[] = [],
    port:          i32  = -1,
    path:          u8[] = [],
    has_query:     bool = false,
    query:         u8[] = [],
    has_fragment:  bool = false,
    fragment:      u8[] = [],
}

// Zero-copy non-allocating URI view referencing slices of the original input.
struct UrlView {
    raw:           const u8[:] = "",
    scheme:        const u8[:] = "",
    has_authority: bool        = false,
    userinfo:      const u8[:] = "",
    host:          const u8[:] = "",
    port:          i32         = -1,
    path:          const u8[:] = "",
    has_query:     bool        = false,
    query:         const u8[:] = "",
    has_fragment:  bool        = false,
    fragment:      const u8[:] = "",
}

struct QueryParam {
    key:   u8[] = [],
    value: u8[] = [],
}

// -----------------------------------------------------------------------------
// Character classification and Lookup Tables (RFC 3986)
// -----------------------------------------------------------------------------

const FLAG_ALPHA:      u8 = 0x01;
const FLAG_DIGIT:      u8 = 0x02;
const FLAG_HEX:        u8 = 0x04;
const FLAG_UNRESERVED: u8 = 0x08;
const FLAG_SUB_DELIM:  u8 = 0x10;
const FLAG_PCHAR:      u8 = 0x20;
const FLAG_SCHEME:     u8 = 0x40;

const CHAR_FLAGS: u8[256] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x30, 0x00, 0x00, 0x30, 0x00, 0x30, 0x30, 0x30, 0x30, 0x30, 0x70, 0x30, 0x68, 0x68, 0x00,
    0x6E, 0x6E, 0x6E, 0x6E, 0x6E, 0x6E, 0x6E, 0x6E, 0x6E, 0x6E, 0x20, 0x30, 0x00, 0x30, 0x00, 0x00,
    0x20, 0x6D, 0x6D, 0x6D, 0x6D, 0x6D, 0x6D, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69,
    0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x00, 0x00, 0x00, 0x00, 0x28,
    0x00, 0x6D, 0x6D, 0x6D, 0x6D, 0x6D, 0x6D, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69,
    0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x69, 0x00, 0x00, 0x00, 0x28, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const HEX_VAL: u8[256] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

fn is_alpha(c: u8) -> bool { (CHAR_FLAGS[c] & FLAG_ALPHA) != 0 }
fn is_digit(c: u8) -> bool { (CHAR_FLAGS[c] & FLAG_DIGIT) != 0 }
fn is_hex_digit(c: u8) -> bool { (CHAR_FLAGS[c] & FLAG_HEX) != 0 }
fn is_unreserved(c: u8) -> bool { (CHAR_FLAGS[c] & FLAG_UNRESERVED) != 0 }
fn is_sub_delim(c: u8) -> bool { (CHAR_FLAGS[c] & FLAG_SUB_DELIM) != 0 }
fn is_pchar(c: u8) -> bool { (CHAR_FLAGS[c] & FLAG_PCHAR) != 0 }
fn is_scheme_char(c: u8) -> bool { (CHAR_FLAGS[c] & FLAG_SCHEME) != 0 }
fn hex_val(c: u8) -> u8 { HEX_VAL[c] }

fn to_lower_ascii(c: u8) -> u8 {
    if c >= 'A' && c <= 'Z' { c + 32 } else { c }
}

// -----------------------------------------------------------------------------
// Percent encoding / decoding
// -----------------------------------------------------------------------------

const HEX_CHARS = "0123456789ABCDEF";

fn percent_decode(input: const u8[:], out: u8[>..]&) -> bool {
    var i = 0;
    while i < input.len {
        let start = i;
        while i < input.len && input[i] != '%' {
            i++;
        }
        if i > start {
            out.append(input[start..i]);
        }
        if i < input.len {
            if i + 2 >= input.len { return false; }
            let h1 = HEX_VAL[input[i + 1]];
            let h2 = HEX_VAL[input[i + 2]];
            if (h1 | h2) >= 0x80 { return false; }
            out.push((h1 << 4) | h2);
            i += 3;
        }
    }
    return true;
}

fn percent_encode(input: const u8[:], out: u8[>..]&) {
    var i = 0;
    while i < input.len {
        let start = i;
        while i < input.len && (CHAR_FLAGS[input[i]] & FLAG_UNRESERVED) != 0 {
            i++;
        }
        if i > start {
            out.append(input[start..i]);
        }
        if i < input.len {
            let c = input[i];
            out.push('%');
            out.push(HEX_CHARS[(c >> 4) & 0x0F]);
            out.push(HEX_CHARS[c & 0x0F]);
            i++;
        }
    }
}

// -----------------------------------------------------------------------------
// Zero-Copy URI View Parsing (RFC 3986)
// -----------------------------------------------------------------------------

fn parse_view(raw: const u8[:]) -> UrlView, Error {
    if raw.len == 0 {
        return UrlView { raw: raw }, Error { .. };
    }
    if raw.len > MAX_URL_BYTES {
        return UrlView { raw: raw }, Error { kind: ErrorKind.TooLong, offset: raw.len };
    }

    var scheme_part: const u8[:] = raw[..0];
    var has_authority = false;
    var userinfo_part: const u8[:] = raw[..0];
    var host_part:     const u8[:] = raw[..0];
    var port_num:      i32         = -1;
    var path_part:     const u8[:] = raw[..0];
    var has_query = false;
    var query_part: const u8[:] = raw[..0];
    var has_fragment = false;
    var fragment_part: const u8[:] = raw[..0];

    var at = 0;

    // 1. Scheme: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":"
    var colon = -1;
    for i in raw.len {
        let c = raw[i];
        if c == ':' { colon = i; break; }
        if c == '/' || c == '?' || c == '#' { break; }
    }

    if colon > 0 {
        if !is_alpha(raw[0]) {
            return UrlView { raw: raw }, Error { kind: ErrorKind.InvalidScheme, offset: 0 };
        }
        for i in 1..colon {
            if !is_scheme_char(raw[i]) {
                return UrlView { raw: raw }, Error { kind: ErrorKind.InvalidScheme, offset: i };
            }
        }
        scheme_part = raw[..colon];
        at = colon + 1;
    }

    // 2. Authority: "//" authority
    if at + 1 < raw.len && raw[at] == '/' && raw[at + 1] == '/' {
        has_authority = true;
        at += 2;
        let auth_start = at;
        var auth_end = raw.len;
        for i in auth_start..raw.len {
            let c = raw[i];
            if c == '/' || c == '?' || c == '#' { auth_end = i; break; }
        }
        let auth = raw[auth_start..auth_end];
        at = auth_end;

        // Parse authority: [ userinfo "@" ] host [ ":" port ]
        var at_sign = -1;
        for i in auth.len {
            if auth[i] == '@' { at_sign = i; }
        }

        var host_port = auth;
        if at_sign >= 0 {
            userinfo_part = auth[..at_sign];
            host_port = auth[at_sign + 1..];
        }

        var hp_host = host_port[..0];
        var hp_port = host_port[..0];
        var has_port = false;

        if host_port.len > 0 && host_port[0] == '[' {
            // IPv6 host
            var close_bracket = -1;
            for i in 1..host_port.len {
                if host_port[i] == ']' { close_bracket = i; break; }
            }
            if close_bracket < 0 {
                return UrlView { raw: raw }, Error { kind: ErrorKind.InvalidHost, offset: auth_start };
            }
            let inner = host_port[1..close_bracket];
            if inner.len == 0 {
                return UrlView { raw: raw }, Error { kind: ErrorKind.InvalidHost, offset: auth_start };
            }
            var has_colon = false;
            for c in inner {
                if c == ':' {
                    has_colon = true;
                } else if !is_hex_digit(c) && c != '.' {
                    return UrlView { raw: raw }, Error { kind: ErrorKind.InvalidHost, offset: auth_start };
                }
            }
            if !has_colon {
                return UrlView { raw: raw }, Error { kind: ErrorKind.InvalidHost, offset: auth_start };
            }
            hp_host = host_port[..close_bracket + 1];
            if close_bracket + 1 < host_port.len {
                if host_port[close_bracket + 1] != ':' {
                    return UrlView { raw: raw }, Error { kind: ErrorKind.InvalidAuthority, offset: auth_start + close_bracket + 1 };
                }
                hp_port = host_port[close_bracket + 2..];
                has_port = true;
            }
        } else {
            // Regular host name / IPv4
            var colon_idx = -1;
            for i in host_port.len {
                if host_port[i] == ':' { colon_idx = i; break; }
            }
            if colon_idx >= 0 {
                hp_host = host_port[..colon_idx];
                hp_port = host_port[colon_idx + 1..];
                has_port = true;
            } else {
                hp_host = host_port;
            }
        }

        host_part = hp_host;

        if has_port {
            if hp_port.len == 0 {
                port_num = -1;
            } else {
                var p: i64 = 0;
                for c in hp_port {
                    if !is_digit(c) {
                        return UrlView { raw: raw }, Error { kind: ErrorKind.InvalidPort, offset: at };
                    }
                    p = p * 10 + (c - '0');
                    if p > 65535 {
                        return UrlView { raw: raw }, Error { kind: ErrorKind.InvalidPort, offset: at };
                    }
                }
                port_num = p as! i32;
            }
        }
    }

    // 3. Path
    let path_start = at;
    var path_end = raw.len;
    for i in path_start..raw.len {
        let c = raw[i];
        if c == '?' || c == '#' { path_end = i; break; }
    }
    path_part = raw[path_start..path_end];
    at = path_end;

    // 4. Query
    if at < raw.len && raw[at] == '?' {
        has_query = true;
        at++;
        let q_start = at;
        var q_end = raw.len;
        for i in q_start..raw.len {
            if raw[i] == '#' { q_end = i; break; }
        }
        query_part = raw[q_start..q_end];
        at = q_end;
    }

    // 5. Fragment
    if at < raw.len && raw[at] == '#' {
        has_fragment = true;
        at++;
        fragment_part = raw[at..];
    }

    return UrlView {
        raw:           raw,
        scheme:        scheme_part,
        has_authority: has_authority,
        userinfo:      userinfo_part,
        host:          host_part,
        port:          port_num,
        path:          path_part,
        has_query:     has_query,
        query:         query_part,
        has_fragment:  has_fragment,
        fragment:      fragment_part,
    }, Error { .. };
}

// -----------------------------------------------------------------------------
// URI Parsing to Owned Url (RFC 3986)
// -----------------------------------------------------------------------------

fn parse(raw: const u8[:]) -> Url, Error {
    let v, err = parse_view(raw);
    if err.kind != ErrorKind.None {
        return Url { .. }, err;
    }

    var scheme_buf: u8[>..] = [];
    var host_buf:   u8[>..] = [];

    // Scheme normalization: lowercase
    var scheme_has_upper = false;
    for c in v.scheme {
        if c >= 'A' && c <= 'Z' { scheme_has_upper = true; break; }
    }
    if scheme_has_upper {
        for c in v.scheme { scheme_buf.push(to_lower_ascii(c)); }
    } else {
        scheme_buf.append(v.scheme);
    }

    // Host normalization: lowercase
    var host_has_upper = false;
    for c in v.host {
        if c >= 'A' && c <= 'Z' { host_has_upper = true; break; }
    }
    if host_has_upper {
        for c in v.host { host_buf.push(to_lower_ascii(c)); }
    } else {
        host_buf.append(v.host);
    }

    var uinfo_buf: u8[>..] = [];
    uinfo_buf.append(v.userinfo);

    var path_buf: u8[>..] = [];
    path_buf.append(v.path);

    var query_buf: u8[>..] = [];
    if v.has_query { query_buf.append(v.query); }

    var frag_buf: u8[>..] = [];
    if v.has_fragment { frag_buf.append(v.fragment); }

    return Url {
        scheme:        scheme_buf,
        has_authority: v.has_authority,
        userinfo:      uinfo_buf,
        host:          host_buf,
        port:          v.port,
        path:          path_buf,
        has_query:     v.has_query,
        query:         query_buf,
        has_fragment:  v.has_fragment,
        fragment:      frag_buf,
    }, Error { .. };
}

// -----------------------------------------------------------------------------
// Format / Reconstruct URI string
// -----------------------------------------------------------------------------

fn format(u: Url&, out: u8[>..]&) {
    if u.scheme.len > 0 {
        out.append(u.scheme);
        out.push(':');
    }
    if u.has_authority {
        out.push('/');
        out.push('/');
        if u.userinfo.len > 0 {
            out.append(u.userinfo);
            out.push('@');
        }
        out.append(u.host);
        if u.port >= 0 {
            out.push(':');
            out.append(str(u.port));
        }
    }
    out.append(u.path);
    if u.has_query {
        out.push('?');
        out.append(u.query);
    }
    if u.has_fragment {
        out.push('#');
        out.append(u.fragment);
    }
}

fn to_string(u: Url&) -> u8[>..] {
    var out: u8[>..] = [];
    format(u, out);
    return out;
}

// -----------------------------------------------------------------------------
// Path Normalization (RFC 3986 Section 5.2.4 Remove Dot Segments)
// -----------------------------------------------------------------------------

fn remove_dot_segments(path: const u8[:], out: u8[>..]&) {
    var at = 0;

    while at < path.len {
        let rem = path[at..];
        // 2.A: If input begins with "../" or "./", remove that prefix
        if rem.len >= 3 && rem[0] == '.' && rem[1] == '.' && rem[2] == '/' {
            at += 3;
            continue;
        }
        if rem.len >= 2 && rem[0] == '.' && rem[1] == '/' {
            at += 2;
            continue;
        }

        // 2.B: If begins with "/./", advance by 2; if "/.", output "/" and advance by 2
        if rem.len >= 3 && rem[0] == '/' && rem[1] == '.' && rem[2] == '/' {
            at += 2;
            continue;
        }
        if rem.len == 2 && rem[0] == '/' && rem[1] == '.' {
            out.push('/');
            at += 2;
            continue;
        }

        // 2.C: If begins with "/../" or "/..", replace with "/" and pop last segment from out
        if (rem.len >= 4 && rem[0] == '/' && rem[1] == '.' && rem[2] == '.' && rem[3] == '/') ||
           (rem.len == 3 && rem[0] == '/' && rem[1] == '.' && rem[2] == '.') {
            let is_exact = rem.len == 3;

            // Remove last segment and its preceding "/" from output buffer (backward scan)
            var last_slash = -1;
            var j = out.len - 1;
            while j >= 0 {
                if out[j] == '/' { last_slash = j; break; }
                j--;
            }
            if last_slash >= 0 {
                while out.len > last_slash { out.pop(); }
            } else {
                out.clear();
            }

            if is_exact {
                out.push('/');
                at += 3;
            } else {
                at += 3; // leaves trailing '/'
            }
            continue;
        }

        // 2.D: If input buffer consists only of "." or "..", remove that
        if (rem.len == 1 && rem[0] == '.') || (rem.len == 2 && rem[0] == '.' && rem[1] == '.') {
            at += rem.len;
            continue;
        }

        // 2.E: Move first path segment to output buffer
        var seg_end = 0;
        if rem[0] == '/' {
            seg_end = 1;
            while seg_end < rem.len && rem[seg_end] != '/' {
                seg_end++;
            }
            out.append(rem[..seg_end]);
        } else {
            while seg_end < rem.len && rem[seg_end] != '/' {
                seg_end++;
            }
            out.append(rem[..seg_end]);
        }
        at += seg_end;
    }
}

// -----------------------------------------------------------------------------
// Reference Resolution (RFC 3986 Section 5.2.2)
// -----------------------------------------------------------------------------

fn merge_paths(base_path: const u8[:], ref_path: const u8[:], has_authority: bool, out: u8[>..]&) {
    if has_authority && base_path.len == 0 {
        out.push('/');
        out.append(ref_path);
        return;
    }

    var last_slash = -1;
    var i = base_path.len - 1;
    while i >= 0 {
        if base_path[i] == '/' { last_slash = i; break; }
        i--;
    }

    if last_slash >= 0 {
        out.append(base_path[..last_slash + 1]);
    }
    out.append(ref_path);
}

fn resolve(base: Url&, reference: const u8[:]) -> Url, Error {
    let r, err = parse(reference);
    if err.kind != ErrorKind.None { return Url { .. }, err; }

    var target_scheme: u8[>..] = [];
    var target_has_authority = false;
    var target_userinfo: u8[>..] = [];
    var target_host:     u8[>..] = [];
    var target_port:     i32     = -1;
    var target_path:     u8[>..] = [];
    var target_has_query = false;
    var target_query: u8[>..] = [];
    var target_has_fragment = false;
    var target_fragment: u8[>..] = [];

    if r.scheme.len > 0 {
        target_scheme.append(r.scheme);
        target_has_authority = r.has_authority;
        target_userinfo.append(r.userinfo);
        target_host.append(r.host);
        target_port = r.port;
        remove_dot_segments(r.path, target_path);
        target_has_query = r.has_query;
        target_query.append(r.query);
    } else {
        if r.has_authority {
            target_has_authority = true;
            target_userinfo.append(r.userinfo);
            target_host.append(r.host);
            target_port = r.port;
            remove_dot_segments(r.path, target_path);
            target_has_query = r.has_query;
            target_query.append(r.query);
        } else {
            if r.path.len == 0 {
                target_path.append(base.path);
                if r.has_query {
                    target_has_query = true;
                    target_query.append(r.query);
                } else {
                    target_has_query = base.has_query;
                    target_query.append(base.query);
                }
            } else {
                if r.path.len > 0 && r.path[0] == '/' {
                    remove_dot_segments(r.path, target_path);
                } else {
                    var merged: u8[>..] = [];
                    merge_paths(base.path, r.path, base.has_authority, merged);
                    remove_dot_segments(merged, target_path);
                }
                target_has_query = r.has_query;
                target_query.append(r.query);
            }
            target_has_authority = base.has_authority;
            target_userinfo.append(base.userinfo);
            target_host.append(base.host);
            target_port = base.port;
        }
        target_scheme.append(base.scheme);
    }
    target_has_fragment = r.has_fragment;
    target_fragment.append(r.fragment);

    return Url {
        scheme:        target_scheme,
        has_authority: target_has_authority,
        userinfo:      target_userinfo,
        host:          target_host,
        port:          target_port,
        path:          target_path,
        has_query:     target_has_query,
        query:         target_query,
        has_fragment:  target_has_fragment,
        fragment:      target_fragment,
    }, Error { .. };
}

// -----------------------------------------------------------------------------
// Application/x-www-form-urlencoded Query String Handling
// -----------------------------------------------------------------------------

fn decode_query_component(input: const u8[:], out: u8[>..]&) -> bool {
    var i = 0;
    while i < input.len {
        let start = i;
        while i < input.len && input[i] != '+' && input[i] != '%' {
            i++;
        }
        if i > start {
            out.append(input[start..i]);
        }
        if i < input.len {
            let c = input[i];
            if c == '+' {
                out.push(' ');
                i++;
            } else { // c == '%'
                if i + 2 >= input.len { return false; }
                let h1 = HEX_VAL[input[i + 1]];
                let h2 = HEX_VAL[input[i + 2]];
                if (h1 | h2) >= 0x80 { return false; }
                out.push((h1 << 4) | h2);
                i += 3;
            }
        }
    }
    return true;
}

fn encode_query_component(input: const u8[:], out: u8[>..]&) {
    var i = 0;
    while i < input.len {
        let start = i;
        while i < input.len && (CHAR_FLAGS[input[i]] & FLAG_UNRESERVED) != 0 {
            i++;
        }
        if i > start {
            out.append(input[start..i]);
        }
        if i < input.len {
            let c = input[i];
            if c == ' ' {
                out.push('+');
            } else {
                out.push('%');
                out.push(HEX_CHARS[(c >> 4) & 0x0F]);
                out.push(HEX_CHARS[c & 0x0F]);
            }
            i++;
        }
    }
}

fn parse_query(query: const u8[:]) -> QueryParam[>..] {
    var params: QueryParam[>..] = [];
    if query.len == 0 { return params; }

    var at = 0;
    while at < query.len && params.len < MAX_QUERY_PARAMS {
        var amp = query.len;
        for i in at..query.len {
            if query[i] == '&' { amp = i; break; }
        }
        let pair = query[at..amp];
        at = amp + 1;
        if pair.len == 0 { continue; }

        var eq = pair.len;
        for i in pair.len {
            if pair[i] == '=' { eq = i; break; }
        }

        var k_buf: u8[>..] = [];
        var v_buf: u8[>..] = [];
        decode_query_component(pair[..eq], k_buf);
        if eq < pair.len {
            decode_query_component(pair[eq + 1..], v_buf);
        }
        params.push(QueryParam { key: copy(k_buf), value: copy(v_buf) });
    }
    return params;
}

fn format_query(params: QueryParam[:], out: u8[>..]&) {
    for p, i in params {
        if i > 0 { out.push('&'); }
        encode_query_component(p.key, out);
        out.push('=');
        encode_query_component(p.value, out);
    }
}

// -----------------------------------------------------------------------------
// WHATWG URL Compatibility Surface
// -----------------------------------------------------------------------------

// URLSearchParams: Inspection and Mutation (WHATWG §6)

fn query_has(params: QueryParam[:], key: const u8[:]) -> bool {
    for p in params {
        if p.key == key { return true; }
    }
    return false;
}

fn query_get(params: QueryParam[:], key: const u8[:], out: u8[>..]&) -> bool {
    for p in params {
        if p.key == key {
            out.append(p.value);
            return true;
        }
    }
    return false;
}

fn query_append(params: QueryParam[>..]&, key: const u8[:], value: const u8[:]) {
    var k_buf: u8[>..] = [];
    k_buf.append(key);
    var v_buf: u8[>..] = [];
    v_buf.append(value);
    params.push(QueryParam { key: copy(k_buf), value: copy(v_buf) });
}

fn query_set(params: QueryParam[>..]&, key: const u8[:], value: const u8[:]) {
    var first_idx = -1;
    var filtered: QueryParam[>..] = [];
    for p in params {
        if p.key == key {
            if first_idx < 0 {
                first_idx = filtered.len;
                var k_buf: u8[>..] = [];
                k_buf.append(key);
                var v_buf: u8[>..] = [];
                v_buf.append(value);
                filtered.push(QueryParam { key: copy(k_buf), value: copy(v_buf) });
            }
        } else {
            var k_buf: u8[>..] = [];
            k_buf.append(p.key);
            var v_buf: u8[>..] = [];
            v_buf.append(p.value);
            filtered.push(QueryParam { key: copy(k_buf), value: copy(v_buf) });
        }
    }
    if first_idx < 0 {
        var k_buf: u8[>..] = [];
        k_buf.append(key);
        var v_buf: u8[>..] = [];
        v_buf.append(value);
        filtered.push(QueryParam { key: copy(k_buf), value: copy(v_buf) });
    }
    params.clear();
    for p in filtered {
        var k_buf: u8[>..] = [];
        k_buf.append(p.key);
        var v_buf: u8[>..] = [];
        v_buf.append(p.value);
        params.push(QueryParam { key: copy(k_buf), value: copy(v_buf) });
    }
}

fn query_delete(params: QueryParam[>..]&, key: const u8[:]) {
    var filtered: QueryParam[>..] = [];
    for p in params {
        if p.key != key {
            var k_buf: u8[>..] = [];
            k_buf.append(p.key);
            var v_buf: u8[>..] = [];
            v_buf.append(p.value);
            filtered.push(QueryParam { key: copy(k_buf), value: copy(v_buf) });
        }
    }
    params.clear();
    for p in filtered {
        var k_buf: u8[>..] = [];
        k_buf.append(p.key);
        var v_buf: u8[>..] = [];
        v_buf.append(p.value);
        params.push(QueryParam { key: copy(k_buf), value: copy(v_buf) });
    }
}

fn get_nth_key(params: QueryParam[:], target_idx: i64) -> const u8[:] {
    for p, i in params {
        if i == target_idx { return p.key; }
    }
    return "";
}

fn bytes_compare(a: const u8[:], b: const u8[:]) -> i32 {
    let min_len = if a.len < b.len { a.len } else { b.len };
    for i in min_len {
        if a[i] < b[i] { return -1; }
        if a[i] > b[i] { return 1; }
    }
    if a.len < b.len { return -1; }
    if a.len > b.len { return 1; }
    return 0;
}

fn query_sort(params: QueryParam[>..]&) {
    if params.len <= 1 { return; }
    var order: i64[>..] = [];
    for i in params.len { order.push(i); }

    // Stable insertion sort on key bytes per WHATWG URL §6.3
    var i = 1;
    while i < order.len {
        let current_idx = order[i];
        let current_key = get_nth_key(params, current_idx);
        var j = i;
        while j > 0 {
            let prev_idx = order[j - 1];
            let prev_key = get_nth_key(params, prev_idx);
            if bytes_compare(prev_key, current_key) > 0 {
                order[j] = prev_idx;
                j--;
            } else {
                break;
            }
        }
        order[j] = current_idx;
        i++;
    }

    var sorted: QueryParam[>..] = [];
    for ord in order {
        for p, idx in params {
            if idx == ord {
                var k_buf: u8[>..] = [];
                k_buf.append(p.key);
                var v_buf: u8[>..] = [];
                v_buf.append(p.value);
                sorted.push(QueryParam { key: copy(k_buf), value: copy(v_buf) });
                break;
            }
        }
    }

    params.clear();
    for p in sorted {
        var k_buf: u8[>..] = [];
        k_buf.append(p.key);
        var v_buf: u8[>..] = [];
        v_buf.append(p.value);
        params.push(QueryParam { key: copy(k_buf), value: copy(v_buf) });
    }
}

// Origin Extraction (WHATWG URL §4.2)

fn default_port_for_scheme(scheme: const u8[:]) -> i32 {
    if scheme == "http" || scheme == "ws" { return 80; }
    if scheme == "https" || scheme == "wss" { return 443; }
    if scheme == "ftp" { return 21; }
    return -1;
}

fn is_special_scheme(scheme: const u8[:]) -> bool {
    scheme == "http" || scheme == "https" || scheme == "ws" || scheme == "wss" || scheme == "ftp"
}

fn origin(u: Url&, out: u8[>..]&) {
    if !is_special_scheme(u.scheme) || !u.has_authority {
        out.append("null");
        return;
    }
    out.append(u.scheme);
    out.append("://");
    out.append(u.host);
    let def_port = default_port_for_scheme(u.scheme);
    if u.port >= 0 && u.port != def_port {
        out.push(':');
        out.append(str(u.port));
    }
}

fn origin_string(u: Url&) -> u8[>..] {
    var out: u8[>..] = [];
    origin(u, out);
    return out;
}

// Cloning and Functional Modifiers (Functional WHATWG Component Mutation)

fn clone_url(u: Url&) -> Url {
    return Url {
        scheme:        copy(u.scheme),
        has_authority: u.has_authority,
        userinfo:      copy(u.userinfo),
        host:          copy(u.host),
        port:          u.port,
        path:          copy(u.path),
        has_query:     u.has_query,
        query:         copy(u.query),
        has_fragment:  u.has_fragment,
        fragment:      copy(u.fragment),
    };
}

fn with_scheme(u: Url&, new_scheme: const u8[:]) -> Url, bool {
    if new_scheme.len == 0 || !is_alpha(new_scheme[0]) { return clone_url(u), false; }
    for i in 1..new_scheme.len {
        if !is_scheme_char(new_scheme[i]) { return clone_url(u), false; }
    }
    var buf: u8[>..] = [];
    for c in new_scheme { buf.push(to_lower_ascii(c)); }
    return Url {
        scheme:        copy(buf),
        has_authority: u.has_authority,
        userinfo:      copy(u.userinfo),
        host:          copy(u.host),
        port:          u.port,
        path:          copy(u.path),
        has_query:     u.has_query,
        query:         copy(u.query),
        has_fragment:  u.has_fragment,
        fragment:      copy(u.fragment),
    }, true;
}

fn with_host(u: Url&, new_host: const u8[:]) -> Url, bool {
    if new_host.len > 0 && new_host[0] == '[' {
        var close_b = -1;
        for i in 1..new_host.len {
            if new_host[i] == ']' { close_b = i; break; }
        }
        if close_b != new_host.len - 1 { return clone_url(u), false; }
        let inner = new_host[1..close_b];
        if inner.len == 0 { return clone_url(u), false; }
        var has_col = false;
        for c in inner {
            if c == ':' { has_col = true; }
            else if !is_hex_digit(c) && c != '.' { return clone_url(u), false; }
        }
        if !has_col { return clone_url(u), false; }
    }
    var buf: u8[>..] = [];
    for c in new_host { buf.push(to_lower_ascii(c)); }
    return Url {
        scheme:        copy(u.scheme),
        has_authority: true,
        userinfo:      copy(u.userinfo),
        host:          copy(buf),
        port:          u.port,
        path:          copy(u.path),
        has_query:     u.has_query,
        query:         copy(u.query),
        has_fragment:  u.has_fragment,
        fragment:      copy(u.fragment),
    }, true;
}

fn with_port(u: Url&, new_port: i32) -> Url, bool {
    if new_port < -1 || new_port > 65535 { return clone_url(u), false; }
    return Url {
        scheme:        copy(u.scheme),
        has_authority: u.has_authority,
        userinfo:      copy(u.userinfo),
        host:          copy(u.host),
        port:          new_port,
        path:          copy(u.path),
        has_query:     u.has_query,
        query:         copy(u.query),
        has_fragment:  u.has_fragment,
        fragment:      copy(u.fragment),
    }, true;
}

fn with_path(u: Url&, new_path: const u8[:]) -> Url {
    var buf: u8[>..] = [];
    remove_dot_segments(new_path, buf);
    return Url {
        scheme:        copy(u.scheme),
        has_authority: u.has_authority,
        userinfo:      copy(u.userinfo),
        host:          copy(u.host),
        port:          u.port,
        path:          copy(buf),
        has_query:     u.has_query,
        query:         copy(u.query),
        has_fragment:  u.has_fragment,
        fragment:      copy(u.fragment),
    };
}

fn with_query(u: Url&, new_query: const u8[:]) -> Url {
    var buf: u8[>..] = [];
    let has_q = new_query.len > 0;
    if has_q { buf.append(new_query); }
    return Url {
        scheme:        copy(u.scheme),
        has_authority: u.has_authority,
        userinfo:      copy(u.userinfo),
        host:          copy(u.host),
        port:          u.port,
        path:          copy(u.path),
        has_query:     has_q,
        query:         copy(buf),
        has_fragment:  u.has_fragment,
        fragment:      copy(u.fragment),
    };
}

fn with_fragment(u: Url&, new_frag: const u8[:]) -> Url {
    var buf: u8[>..] = [];
    let has_f = new_frag.len > 0;
    if has_f { buf.append(new_frag); }
    return Url {
        scheme:        copy(u.scheme),
        has_authority: u.has_authority,
        userinfo:      copy(u.userinfo),
        host:          copy(u.host),
        port:          u.port,
        path:          copy(u.path),
        has_query:     u.has_query,
        query:         copy(u.query),
        has_fragment:  has_f,
        fragment:      copy(buf),
    };
}
