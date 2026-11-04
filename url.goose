// SPDX-License-Identifier: Apache-2.0
// Pure Goose implementation of RFC 3986 Uniform Resource Identifiers.
namespace url;
import std;
import .address;

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
    has_userinfo:  bool = false,
    has_port:      bool = false,
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
    has_userinfo:  bool        = false,
    has_port:      bool        = false,
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

// Modes: 0=userinfo, 1=reg-name, 2=path, 3=query/fragment.
fn component_error(input: const u8[:], mode: i64, kind: ErrorKind, offset: i64 = 0) -> Error {
    var at = 0;
    while at < input.len {
        let c = input[at];
        if c == '%' {
            if at + 2 >= input.len || !is_hex_digit(input[at + 1]) || !is_hex_digit(input[at + 2]) {
                return Error { kind: ErrorKind.InvalidPercentEncoding, offset: offset + at };
            }
            at += 3; continue;
        }
        if !(is_unreserved(c) || is_sub_delim(c) || (mode != 1 && c == ':') ||
             (mode >= 2 && (c == '@' || c == '/')) || (mode == 3 && c == '?')) {
            return Error { kind: kind, offset: offset + at };
        }
        at++;
    }
    return Error { .. };
}

fn host_error(host: const u8[:], offset: i64 = 0) -> Error {
    if host.len > 0 && host[0] == '[' {
        if host.len < 3 || host[host.len - 1] != ']' || !url_address::valid_literal(host[1..host.len - 1]) {
            return Error { kind: ErrorKind.InvalidHost, offset: offset };
        }
        return Error { .. };
    }
    return component_error(host, 1, ErrorKind.InvalidHost, offset);
}

fn path_error(path: const u8[:], authority: bool, scheme: bool, offset: i64 = 0) -> Error {
    if authority && path.len > 0 && path[0] != '/' { return Error { kind: ErrorKind.InvalidPath, offset: offset }; }
    if !authority && path.len >= 2 && path[..2] == "//" { return Error { kind: ErrorKind.InvalidPath, offset: offset }; }
    if !authority && !scheme {
        for c, i in path { if c == '/' { break; } if c == ':' { return Error { kind: ErrorKind.InvalidPath, offset: offset + i }; } }
    }
    return component_error(path, 2, ErrorKind.InvalidPath, offset);
}

fn percent_decode(input: const u8[:], out: u8[>..]&) -> bool {
    if !decode_fits(input, out.len) { return false; }
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

fn decode_fits(input: const u8[:], prefix: i64) -> bool {
    if input.len > MAX_URL_BYTES || prefix > MAX_URL_BYTES { return false; }
    var at = 0; var size = prefix;
    while at < input.len {
        if input[at] == '%' {
            if at + 2 >= input.len || !is_hex_digit(input[at + 1]) || !is_hex_digit(input[at + 2]) { return false; }
            at += 3;
        } else { at++; }
        size++; if size > MAX_URL_BYTES { return false; }
    }
    return true;
}

fn encoded_safe(c: u8, form: bool) -> bool {
    if form { return is_alpha(c) || is_digit(c) || c == '*' || c == '-' || c == '.' || c == '_'; }
    return is_unreserved(c);
}

fn encoded_size(input: const u8[:], form: bool) -> i64 {
    if input.len > MAX_URL_BYTES { return -1; }
    var size = 0;
    for c in input {
        size += if encoded_safe(c, form) || (form && c == ' ') { 1 } else { 3 };
        if size > MAX_URL_BYTES { return -1; }
    }
    return size;
}

fn percent_encode(input: const u8[:], out: u8[>..]&) -> bool {
    let size = encoded_size(input, false);
    if size < 0 || out.len > MAX_URL_BYTES - size { return false; }
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
    return true;
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
    var has_userinfo = false;
    var port_present = false;
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

    if colon == 0 { return UrlView { raw: raw }, Error { kind: ErrorKind.InvalidPath, offset: 0 }; }
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
            has_userinfo = true;
            userinfo_part = auth[..at_sign];
            host_port = auth[at_sign + 1..];
            let error = component_error(userinfo_part, 0, ErrorKind.InvalidUserinfo, auth_start);
            if error.kind != ErrorKind.None { return UrlView { raw: raw }, error; }
        }

        let host_start = auth_start + (if at_sign >= 0 { at_sign + 1 } else { 0 });
        var hp_host = host_port[..0];
        var hp_port = host_port[..0];
        var has_port = false;

        if host_port.len > 0 && host_port[0] == '[' {
            // RFC IPv6 / IPvFuture literal.
            var close_bracket = -1;
            for i in 1..host_port.len {
                if host_port[i] == ']' { close_bracket = i; break; }
            }
            if close_bracket < 0 {
                return UrlView { raw: raw }, Error { kind: ErrorKind.InvalidHost, offset: host_start };
            }
            let inner = host_port[1..close_bracket];
            if inner.len == 0 {
                return UrlView { raw: raw }, Error { kind: ErrorKind.InvalidHost, offset: host_start };
            }
            if !url_address::valid_literal(inner) {
                return UrlView { raw: raw }, Error { kind: ErrorKind.InvalidHost, offset: host_start };
            }
            hp_host = host_port[..close_bracket + 1];
            if close_bracket + 1 < host_port.len {
                if host_port[close_bracket + 1] != ':' {
                    return UrlView { raw: raw }, Error { kind: ErrorKind.InvalidAuthority, offset: host_start + close_bracket + 1 };
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
        let host_err = host_error(host_part, host_start);
        if host_err.kind != ErrorKind.None { return UrlView { raw: raw }, host_err; }
        port_present = has_port;

        if has_port {
            if hp_port.len == 0 {
                port_num = -1;
            } else {
                var p: i64 = 0;
                for c, i in hp_port {
                    if !is_digit(c) {
                        return UrlView { raw: raw }, Error { kind: ErrorKind.InvalidPort, offset: host_start + hp_host.len + 1 + i };
                    }
                    p = p * 10 + (c - '0');
                    if p > 65535 {
                        return UrlView { raw: raw }, Error { kind: ErrorKind.InvalidPort, offset: host_start + hp_host.len + 1 + i };
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
    let path_err = path_error(path_part, has_authority, scheme_part.len > 0, path_start);
    if path_err.kind != ErrorKind.None { return UrlView { raw: raw }, path_err; }
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
        let query_err = component_error(query_part, 3, ErrorKind.InvalidQuery, q_start);
        if query_err.kind != ErrorKind.None { return UrlView { raw: raw }, query_err; }
        at = q_end;
    }

    // 5. Fragment
    if at < raw.len && raw[at] == '#' {
        has_fragment = true;
        at++;
        fragment_part = raw[at..];
        let fragment_err = component_error(fragment_part, 3, ErrorKind.InvalidFragment, at);
        if fragment_err.kind != ErrorKind.None { return UrlView { raw: raw }, fragment_err; }
    }

    return UrlView {
        raw:           raw,
        scheme:        scheme_part,
        has_authority: has_authority,
        has_userinfo:  has_userinfo,
        has_port:      port_present,
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
        has_userinfo:  v.has_userinfo,
        has_port:      v.has_port,
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

fn wire_size(u: Url&) -> i64 {
    return u.scheme.len + (if u.scheme.len > 0 { 1 } else { 0 }) +
        (if u.has_authority { 2 } else { 0 }) + u.userinfo.len + (if u.has_userinfo { 1 } else { 0 }) +
        u.host.len + (if u.has_port { 1 } else { 0 }) + (if u.port >= 0 { str(u.port).len } else { 0 }) +
        u.path.len + u.query.len + (if u.has_query { 1 } else { 0 }) +
        u.fragment.len + (if u.has_fragment { 1 } else { 0 });
}

fn validate_url(u: Url&) -> Error {
    for field in [u.scheme[..], u.userinfo[..], u.host[..], u.path[..], u.query[..], u.fragment[..]] {
        if field.len > MAX_URL_BYTES { return Error { kind: ErrorKind.TooLong }; }
    }
    if u.scheme.len > 0 {
        if !is_alpha(u.scheme[0]) { return Error { kind: ErrorKind.InvalidScheme }; }
        for c in u.scheme { if !is_scheme_char(c) { return Error { kind: ErrorKind.InvalidScheme }; } }
    }
    if !u.has_authority && (u.has_userinfo || u.has_port || u.userinfo.len > 0 || u.host.len > 0 || u.port != -1) {
        return Error { kind: ErrorKind.InvalidAuthority };
    }
    if (!u.has_userinfo && u.userinfo.len > 0) || (!u.has_port && u.port != -1) || u.port < -1 || u.port > 65535 {
        return Error { kind: ErrorKind.InvalidAuthority };
    }
    if (!u.has_query && u.query.len > 0) || (!u.has_fragment && u.fragment.len > 0) {
        return Error { kind: ErrorKind.InvalidQuery };
    }
    let user_error = component_error(u.userinfo, 0, ErrorKind.InvalidUserinfo);
    if user_error.kind != ErrorKind.None { return user_error; }
    let host_err = host_error(u.host); if host_err.kind != ErrorKind.None { return host_err; }
    let path_err = path_error(u.path, u.has_authority, u.scheme.len > 0); if path_err.kind != ErrorKind.None { return path_err; }
    let query_err = component_error(u.query, 3, ErrorKind.InvalidQuery); if query_err.kind != ErrorKind.None { return query_err; }
    let fragment_err = component_error(u.fragment, 3, ErrorKind.InvalidFragment); if fragment_err.kind != ErrorKind.None { return fragment_err; }
    if wire_size(u) > MAX_URL_BYTES { return Error { kind: ErrorKind.TooLong }; }
    return Error { .. };
}

fn format(u: Url&, out: u8[>..]&) -> Error {
    let error = validate_url(u); if error.kind != ErrorKind.None { return error; }
    if out.len > MAX_URL_BYTES - wire_size(u) { return Error { kind: ErrorKind.TooLong }; }
    if u.scheme.len > 0 {
        out.append(u.scheme);
        out.push(':');
    }
    if u.has_authority {
        out.push('/');
        out.push('/');
        if u.has_userinfo {
            out.append(u.userinfo);
            out.push('@');
        }
        out.append(u.host);
        if u.has_port {
            out.push(':');
            if u.port >= 0 { out.append(str(u.port)); }
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
    return Error { .. };
}

fn to_string(u: Url&) -> u8[>..], Error {
    var out: u8[>..] = [];
    let error = format(u, out);
    return out, error;
}

// -----------------------------------------------------------------------------
// Path Normalization (RFC 3986 Section 5.2.4 Remove Dot Segments)
// -----------------------------------------------------------------------------

fn remove_dot_segments(path: const u8[:], out: u8[>..]&) -> bool {
    if path.len > MAX_URL_BYTES || out.len > MAX_URL_BYTES { return false; }
    var normalized: u8[>..] = [];
    dot_segments_into(path, normalized);
    if normalized.len > MAX_URL_BYTES - out.len { return false; }
    out.append(normalized); return true;
}

// Internal: resolution may construct at most two bounded paths before reducing.
fn dot_segments_into(path: const u8[:], out: u8[>..]&) {
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
    let base_error = validate_url(base);
    if base_error.kind != ErrorKind.None { return Url { .. }, base_error; }
    if base.scheme.len == 0 { return Url { .. }, Error { kind: ErrorKind.InvalidScheme }; }
    let r, err = parse(reference);
    if err.kind != ErrorKind.None { return Url { .. }, err; }

    var target_scheme: u8[>..] = [];
    var target_has_authority = false;
    var target_has_userinfo = false;
    var target_has_port = false;
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
        target_has_userinfo = r.has_userinfo;
        target_has_port = r.has_port;
        target_userinfo.append(r.userinfo);
        target_host.append(r.host);
        target_port = r.port;
        dot_segments_into(r.path, target_path);
        target_has_query = r.has_query;
        target_query.append(r.query);
    } else {
        if r.has_authority {
            target_has_authority = true;
            target_has_userinfo = r.has_userinfo;
            target_has_port = r.has_port;
            target_userinfo.append(r.userinfo);
            target_host.append(r.host);
            target_port = r.port;
            dot_segments_into(r.path, target_path);
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
                    dot_segments_into(r.path, target_path);
                } else {
                    var merged: u8[>..] = [];
                    merge_paths(base.path, r.path, base.has_authority, merged);
                    dot_segments_into(merged, target_path);
                }
                target_has_query = r.has_query;
                target_query.append(r.query);
            }
            target_has_authority = base.has_authority;
            target_has_userinfo = base.has_userinfo;
            target_has_port = base.has_port;
            target_userinfo.append(base.userinfo);
            target_host.append(base.host);
            target_port = base.port;
        }
        target_scheme.append(base.scheme);
    }
    target_has_fragment = r.has_fragment;
    target_fragment.append(r.fragment);

    var target = Url {
        scheme:        copy(target_scheme),
        has_authority: target_has_authority,
        has_userinfo:  target_has_userinfo,
        has_port:      target_has_port,
        userinfo:      copy(target_userinfo),
        host:          copy(target_host),
        port:          target_port,
        path:          copy(target_path),
        has_query:     target_has_query,
        query:         copy(target_query),
        has_fragment:  target_has_fragment,
        fragment:      copy(target_fragment),
    };
    let target_error = validate_url(target);
    if target_error.kind != ErrorKind.None { return Url { .. }, target_error; }
    return target, Error { .. };
}

// -----------------------------------------------------------------------------
// Application/x-www-form-urlencoded Query String Handling
// -----------------------------------------------------------------------------

fn decode_query_component(input: const u8[:], out: u8[>..]&) -> bool {
    if !decode_fits(input, out.len) { return false; }
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

fn encode_query_component(input: const u8[:], out: u8[>..]&) -> bool {
    let size = encoded_size(input, true);
    if size < 0 || out.len > MAX_URL_BYTES - size { return false; }
    var i = 0;
    while i < input.len {
        let start = i;
        while i < input.len && encoded_safe(input[i], true) {
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
    return true;
}

fn parse_query(query: const u8[:]) -> QueryParam[>..], Error {
    var params: QueryParam[>..] = [];
    if query.len > MAX_URL_BYTES { return params, Error { kind: ErrorKind.TooLong }; }
    if query.len == 0 { return params, Error { .. }; }

    var at = 0;
    while at < query.len {
        let start = at;
        var amp = query.len;
        for i in at..query.len {
            if query[i] == '&' { amp = i; break; }
        }
        let pair = query[at..amp];
        at = amp + 1;
        if pair.len == 0 { continue; }
        if params.len >= MAX_QUERY_PARAMS { return [], Error { kind: ErrorKind.TooLong, offset: start }; }

        var eq = pair.len;
        for i in pair.len {
            if pair[i] == '=' { eq = i; break; }
        }

        var k_buf: u8[>..] = [];
        var v_buf: u8[>..] = [];
        if !decode_query_component(pair[..eq], k_buf) { return [], Error { kind: ErrorKind.InvalidPercentEncoding, offset: start }; }
        if eq < pair.len {
            if !decode_query_component(pair[eq + 1..], v_buf) { return [], Error { kind: ErrorKind.InvalidPercentEncoding, offset: start + eq + 1 }; }
        }
        params.push(QueryParam { key: copy(k_buf), value: copy(v_buf) });
    }
    return params, Error { .. };
}

fn query_size(params: QueryParam[:]) -> i64 {
    if params.len > MAX_QUERY_PARAMS { return -1; }
    var size = if params.len > 0 { params.len - 1 } else { 0 };
    for p in params {
        let k = encoded_size(p.key, true); let v = encoded_size(p.value, true);
        if k < 0 || v < 0 { return -1; }
        size += k + v + 1; if size > MAX_URL_BYTES { return -1; }
    }
    return size;
}

fn format_query(params: QueryParam[:], out: u8[>..]&) -> bool {
    let size = query_size(params);
    if size < 0 || out.len > MAX_URL_BYTES - size { return false; }
    for p, i in params {
        if i > 0 { out.push('&'); }
        encode_query_component(p.key, out);
        out.push('=');
        encode_query_component(p.value, out);
    }
    return true;
}

// -----------------------------------------------------------------------------
// Bounded byte-oriented query and component helpers
// -----------------------------------------------------------------------------

// Decoded byte query inspection and mutation

fn query_has(params: QueryParam[:], key: const u8[:]) -> bool {
    if !query_storage_valid(params) || key.len > MAX_URL_BYTES { return false; }
    for p in params {
        if p.key == key { return true; }
    }
    return false;
}

fn query_get(params: QueryParam[:], key: const u8[:], out: u8[>..]&) -> bool {
    if !query_storage_valid(params) || key.len > MAX_URL_BYTES { return false; }
    for p in params {
        if p.key == key {
            if out.len > MAX_URL_BYTES - p.value.len { return false; }
            out.append(p.value);
            return true;
        }
    }
    return false;
}

fn query_storage_valid(params: QueryParam[:]) -> bool {
    if params.len > MAX_QUERY_PARAMS { return false; }
    var size = 0;
    for p in params {
        if p.key.len > MAX_URL_BYTES || p.value.len > MAX_URL_BYTES { return false; }
        size += p.key.len + p.value.len; if size > MAX_URL_BYTES { return false; }
    }
    return true;
}

fn query_append(params: QueryParam[>..]&, key: const u8[:], value: const u8[:]) -> bool {
    let old = query_size(params); let k = encoded_size(key, true); let v = encoded_size(value, true);
    if params.len >= MAX_QUERY_PARAMS || old < 0 || k < 0 || v < 0 ||
       old + k + v + 1 + (if params.len > 0 { 1 } else { 0 }) > MAX_URL_BYTES { return false; }
    var k_buf: u8[>..] = [];
    k_buf.append(key);
    var v_buf: u8[>..] = [];
    v_buf.append(value);
    params.push(QueryParam { key: copy(k_buf), value: copy(v_buf) });
    return true;
}

fn query_set(params: QueryParam[>..]&, key: const u8[:], value: const u8[:]) -> bool {
    if !query_storage_valid(params) || encoded_size(key, true) < 0 || encoded_size(value, true) < 0 { return false; }
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
    if query_size(filtered) < 0 { return false; }
    params.clear();
    for p in filtered {
        var k_buf: u8[>..] = [];
        k_buf.append(p.key);
        var v_buf: u8[>..] = [];
        v_buf.append(p.value);
        params.push(QueryParam { key: copy(k_buf), value: copy(v_buf) });
    }
    return true;
}

fn query_delete(params: QueryParam[>..]&, key: const u8[:]) -> bool {
    if !query_storage_valid(params) || key.len > MAX_URL_BYTES { return false; }
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
    return true;
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

fn query_order(params: QueryParam[:]) -> i64[>..] {
    var order: i64[>..]         = [];
    var keys:  const u8[:][>..] = [];
    for p in params { keys.push(p.key); }
    for i in params.len { order.push(i); }

    // Stable byte ordering (not WHATWG's UTF-16 ordering).
    var i = 1;
    while i < order.len {
        let current_idx = order[i];
        let current_key = keys[current_idx];
        var j = i;
        while j > 0 {
            let prev_idx = order[j - 1];
            let prev_key = keys[prev_idx];
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
    return order;
}

fn query_sort(params: QueryParam[>..]&) -> bool {
    if !query_storage_valid(params) { return false; }
    if params.len <= 1 { return true; }
    let order = query_order(params);

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
    return true;
}

// Limited scheme/authority tuple; not a browser origin or security identity.

fn default_port_for_scheme(scheme: const u8[:]) -> i32 {
    if scheme == "http" || scheme == "ws" { return 80; }
    if scheme == "https" || scheme == "wss" { return 443; }
    if scheme == "ftp" { return 21; }
    return -1;
}

fn is_special_scheme(scheme: const u8[:]) -> bool {
    scheme == "http" || scheme == "https" || scheme == "ws" || scheme == "wss" || scheme == "ftp"
}

fn origin(u: Url&, out: u8[>..]&) -> bool {
    if validate_url(u).kind != ErrorKind.None { return false; }
    var part: u8[>..] = [];
    if !is_special_scheme(u.scheme) || !u.has_authority || u.host.len == 0 {
        part.append("null");
    } else {
        part.append(u.scheme); part.append("://"); part.append(u.host);
        let def_port = default_port_for_scheme(u.scheme);
        if u.port >= 0 && u.port != def_port { part.push(':'); part.append(str(u.port)); }
    }
    if out.len > MAX_URL_BYTES - part.len { return false; }
    out.append(part); return true;
}

fn origin_string(u: Url&) -> u8[>..] {
    var out: u8[>..] = [];
    origin(u, out);
    return out;
}

// Cloning and checked component modifiers

// Internal: only used after validate_url has bounded the original.
fn _clone_url(u: Url&) -> Url {
    return Url {
        scheme:        copy(u.scheme),
        has_authority: u.has_authority,
        has_userinfo:  u.has_userinfo,
        has_port:      u.has_port,
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
    if validate_url(u).kind != ErrorKind.None { return Url { .. }, false; }
    if new_scheme.len > MAX_URL_BYTES { return _clone_url(u), false; }
    if new_scheme.len == 0 || !is_alpha(new_scheme[0]) { return _clone_url(u), false; }
    for i in 1..new_scheme.len {
        if !is_scheme_char(new_scheme[i]) { return _clone_url(u), false; }
    }
    var buf: u8[>..] = [];
    for c in new_scheme { buf.push(to_lower_ascii(c)); }
    var candidate = Url {
        scheme:        copy(buf),
        has_authority: u.has_authority,
        has_userinfo:  u.has_userinfo,
        has_port:      u.has_port,
        userinfo:      copy(u.userinfo),
        host:          copy(u.host),
        port:          u.port,
        path:          copy(u.path),
        has_query:     u.has_query,
        query:         copy(u.query),
        has_fragment:  u.has_fragment,
        fragment:      copy(u.fragment),
    };
    if validate_url(candidate).kind != ErrorKind.None { return _clone_url(u), false; }
    return candidate, true;
}

fn with_host(u: Url&, new_host: const u8[:]) -> Url, bool {
    if validate_url(u).kind != ErrorKind.None { return Url { .. }, false; }
    if new_host.len > MAX_URL_BYTES { return _clone_url(u), false; }
    if host_error(new_host).kind != ErrorKind.None { return _clone_url(u), false; }
    var buf: u8[>..] = [];
    for c in new_host { buf.push(to_lower_ascii(c)); }
    var candidate = Url {
        scheme:        copy(u.scheme),
        has_authority: true,
        has_userinfo:  u.has_userinfo,
        has_port:      u.has_port,
        userinfo:      copy(u.userinfo),
        host:          copy(buf),
        port:          u.port,
        path:          copy(u.path),
        has_query:     u.has_query,
        query:         copy(u.query),
        has_fragment:  u.has_fragment,
        fragment:      copy(u.fragment),
    };
    if validate_url(candidate).kind != ErrorKind.None { return _clone_url(u), false; }
    return candidate, true;
}

fn with_port(u: Url&, new_port: i32) -> Url, bool {
    if validate_url(u).kind != ErrorKind.None { return Url { .. }, false; }
    if new_port < -1 || new_port > 65535 { return _clone_url(u), false; }
    var candidate = Url {
        scheme:        copy(u.scheme),
        has_authority: u.has_authority,
        has_userinfo:  u.has_userinfo,
        has_port:      new_port >= 0,
        userinfo:      copy(u.userinfo),
        host:          copy(u.host),
        port:          new_port,
        path:          copy(u.path),
        has_query:     u.has_query,
        query:         copy(u.query),
        has_fragment:  u.has_fragment,
        fragment:      copy(u.fragment),
    };
    if validate_url(candidate).kind != ErrorKind.None { return _clone_url(u), false; }
    return candidate, true;
}

fn with_path(u: Url&, new_path: const u8[:]) -> Url, bool {
    if validate_url(u).kind != ErrorKind.None { return Url { .. }, false; }
    if new_path.len > MAX_URL_BYTES { return _clone_url(u), false; }
    if path_error(new_path, u.has_authority, u.scheme.len > 0).kind != ErrorKind.None { return _clone_url(u), false; }
    var buf: u8[>..] = [];
    remove_dot_segments(new_path, buf);
    var candidate = Url {
        scheme:        copy(u.scheme),
        has_authority: u.has_authority,
        has_userinfo:  u.has_userinfo,
        has_port:      u.has_port,
        userinfo:      copy(u.userinfo),
        host:          copy(u.host),
        port:          u.port,
        path:          copy(buf),
        has_query:     u.has_query,
        query:         copy(u.query),
        has_fragment:  u.has_fragment,
        fragment:      copy(u.fragment),
    };
    if validate_url(candidate).kind != ErrorKind.None { return _clone_url(u), false; }
    return candidate, true;
}

fn with_query(u: Url&, new_query: const u8[:]) -> Url, bool {
    if validate_url(u).kind != ErrorKind.None { return Url { .. }, false; }
    if new_query.len > MAX_URL_BYTES { return _clone_url(u), false; }
    var buf: u8[>..] = [];
    let has_q = new_query.len > 0;
    if has_q { buf.append(new_query); }
    var candidate = Url {
        scheme:        copy(u.scheme),
        has_authority: u.has_authority,
        has_userinfo:  u.has_userinfo,
        has_port:      u.has_port,
        userinfo:      copy(u.userinfo),
        host:          copy(u.host),
        port:          u.port,
        path:          copy(u.path),
        has_query:     has_q,
        query:         copy(buf),
        has_fragment:  u.has_fragment,
        fragment:      copy(u.fragment),
    };
    if validate_url(candidate).kind != ErrorKind.None { return _clone_url(u), false; }
    return candidate, true;
}

fn with_fragment(u: Url&, new_frag: const u8[:]) -> Url, bool {
    if validate_url(u).kind != ErrorKind.None { return Url { .. }, false; }
    if new_frag.len > MAX_URL_BYTES { return _clone_url(u), false; }
    var buf: u8[>..] = [];
    let has_f = new_frag.len > 0;
    if has_f { buf.append(new_frag); }
    var candidate = Url {
        scheme:        copy(u.scheme),
        has_authority: u.has_authority,
        has_userinfo:  u.has_userinfo,
        has_port:      u.has_port,
        userinfo:      copy(u.userinfo),
        host:          copy(u.host),
        port:          u.port,
        path:          copy(u.path),
        has_query:     u.has_query,
        query:         copy(u.query),
        has_fragment:  has_f,
        fragment:      copy(buf),
    };
    if validate_url(candidate).kind != ErrorKind.None { return _clone_url(u), false; }
    return candidate, true;
}
