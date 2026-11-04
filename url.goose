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

struct QueryParam {
    key:   u8[] = [],
    value: u8[] = [],
}

// -----------------------------------------------------------------------------
// Character classification
// -----------------------------------------------------------------------------

fn is_alpha(c: u8) -> bool {
    (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

fn is_digit(c: u8) -> bool {
    c >= '0' && c <= '9'
}

fn is_hex_digit(c: u8) -> bool {
    is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

fn hex_val(c: u8) -> u8 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    if c >= 'A' && c <= 'F' { return c - 'A' + 10; }
    return 0;
}

fn to_lower_ascii(c: u8) -> u8 {
    if c >= 'A' && c <= 'Z' { c + 32 } else { c }
}

fn is_unreserved(c: u8) -> bool {
    is_alpha(c) || is_digit(c) || c == '-' || c == '.' || c == '_' || c == '~'
}

fn is_sub_delim(c: u8) -> bool {
    c == '!' || c == '$' || c == '&' || c == '\'' || c == '(' || c == ')' ||
    c == '*' || c == '+' || c == ',' || c == ';' || c == '='
}

fn is_pchar(c: u8) -> bool {
    is_unreserved(c) || is_sub_delim(c) || c == ':' || c == '@'
}

// -----------------------------------------------------------------------------
// Percent encoding / decoding
// -----------------------------------------------------------------------------

const HEX_CHARS = "0123456789ABCDEF";

fn percent_decode(input: const u8[:], out: u8[>..]&) -> bool {
    var i = 0;
    while i < input.len {
        let c = input[i];
        if c == '%' {
            if i + 2 >= input.len { return false; }
            let h1 = input[i + 1];
            let h2 = input[i + 2];
            if !is_hex_digit(h1) || !is_hex_digit(h2) { return false; }
            let byte_val = (hex_val(h1) << 4) | hex_val(h2);
            out.push(byte_val);
            i += 3;
        } else {
            out.push(c);
            i++;
        }
    }
    return true;
}

fn percent_encode(input: const u8[:], out: u8[>..]&) {
    for c in input {
        if is_unreserved(c) {
            out.push(c);
        } else {
            out.push('%');
            out.push(HEX_CHARS[(c >> 4) & 0x0F]);
            out.push(HEX_CHARS[c & 0x0F]);
        }
    }
}

// -----------------------------------------------------------------------------
// URI Parsing (RFC 3986)
// -----------------------------------------------------------------------------

fn parse(raw: const u8[:]) -> Url, Error {
    if raw.len == 0 {
        return Url { .. }, Error { .. };
    }
    if raw.len > MAX_URL_BYTES {
        return Url { .. }, Error { kind: ErrorKind.TooLong, offset: raw.len };
    }

    var scheme_buf: u8[>..] = [];
    var has_authority = false;
    var userinfo_buf: u8[>..] = [];
    var host_buf:     u8[>..] = [];
    var port_num:     i32     = -1;
    var path_buf:     u8[>..] = [];
    var has_query = false;
    var query_buf: u8[>..] = [];
    var has_fragment = false;
    var fragment_buf: u8[>..] = [];

    var at = 0;

    // 1. Scheme: ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ) ":"
    var colon = -1;
    for i in raw.len {
        let c = raw[i];
        if c == ':' { colon = i; break; }
        if c == '/' || c == '?' || c == '#' { break; }
    }

    if colon > 0 {
        // Validate scheme
        if !is_alpha(raw[0]) {
            return Url { .. }, Error { kind: ErrorKind.InvalidScheme, offset: 0 };
        }
        for i in 1..colon {
            let c = raw[i];
            if !is_alpha(c) && !is_digit(c) && c != '+' && c != '-' && c != '.' {
                return Url { .. }, Error { kind: ErrorKind.InvalidScheme, offset: i };
            }
        }
        // Normalize scheme to lowercase
        for i in colon { scheme_buf.push(to_lower_ascii(raw[i])); }
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
            // Userinfo present
            let uinfo = auth[..at_sign];
            for c in uinfo { userinfo_buf.push(c); }
            host_port = auth[at_sign + 1..];
        }

        // Host and Port: IPv6 is enclosed in '[' ']'
        var host_part = host_port[..0];
        var port_part = host_port[..0];
        var has_port = false;

        if host_port.len > 0 && host_port[0] == '[' {
            // IPv6 host
            var close_bracket = -1;
            for i in 1..host_port.len {
                if host_port[i] == ']' { close_bracket = i; break; }
            }
            if close_bracket < 0 {
                return Url { .. }, Error { kind: ErrorKind.InvalidHost, offset: auth_start };
            }
            host_part = host_port[..close_bracket + 1];
            if close_bracket + 1 < host_port.len {
                if host_port[close_bracket + 1] != ':' {
                    return Url { .. }, Error { kind: ErrorKind.InvalidAuthority, offset: auth_start + close_bracket + 1 };
                }
                port_part = host_port[close_bracket + 2..];
                has_port = true;
            }
        } else {
            // Regular host name / IPv4
            var colon_idx = -1;
            for i in host_port.len {
                if host_port[i] == ':' { colon_idx = i; break; }
            }
            if colon_idx >= 0 {
                host_part = host_port[..colon_idx];
                port_part = host_port[colon_idx + 1..];
                has_port = true;
            } else {
                host_part = host_port;
            }
        }

        // Normalize host to lowercase
        for c in host_part { host_buf.push(to_lower_ascii(c)); }

        if has_port {
            if port_part.len == 0 {
                port_num = -1;
            } else {
                var p: i64 = 0;
                for c in port_part {
                    if !is_digit(c) {
                        return Url { .. }, Error { kind: ErrorKind.InvalidPort, offset: at };
                    }
                    p = p * 10 + (c - '0');
                    if p > 65535 {
                        return Url { .. }, Error { kind: ErrorKind.InvalidPort, offset: at };
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
    let pslice = raw[path_start..path_end];
    for c in pslice { path_buf.push(c); }
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
        let qslice = raw[q_start..q_end];
        for c in qslice { query_buf.push(c); }
        at = q_end;
    }

    // 5. Fragment
    if at < raw.len && raw[at] == '#' {
        has_fragment = true;
        at++;
        let fslice = raw[at..];
        for c in fslice { fragment_buf.push(c); }
    }

    return Url {
        scheme:        scheme_buf,
        has_authority: has_authority,
        userinfo:      userinfo_buf,
        host:          host_buf,
        port:          port_num,
        path:          path_buf,
        has_query:     has_query,
        query:         query_buf,
        has_fragment:  has_fragment,
        fragment:      fragment_buf,
    }, Error { .. };
}

// -----------------------------------------------------------------------------
// Format / Reconstruct URI string
// -----------------------------------------------------------------------------

fn format(u: Url&, out: u8[>..]&) {
    if u.scheme.len > 0 {
        for c in u.scheme { out.push(c); }
        out.push(':');
    }
    if u.has_authority {
        out.push('/');
        out.push('/');
        if u.userinfo.len > 0 {
            for c in u.userinfo { out.push(c); }
            out.push('@');
        }
        for c in u.host { out.push(c); }
        if u.port >= 0 {
            out.push(':');
            var port_str = str(u.port);
            for c in port_str { out.push(c); }
        }
    }
    for c in u.path { out.push(c); }
    if u.has_query {
        out.push('?');
        for c in u.query { out.push(c); }
    }
    if u.has_fragment {
        out.push('#');
        for c in u.fragment { out.push(c); }
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

        // 2.B: If begins with "/./", advance by 2 (leaving '/'); if "/.", output "/" and advance by 2
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

            // Remove last segment and its preceding "/" (if any) from output buffer
            var last_slash = -1;
            for i in out.len {
                if out[i] == '/' { last_slash = i; }
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
            out.push('/');
            seg_end = 1;
            while seg_end < rem.len && rem[seg_end] != '/' {
                out.push(rem[seg_end]);
                seg_end++;
            }
        } else {
            while seg_end < rem.len && rem[seg_end] != '/' {
                out.push(rem[seg_end]);
                seg_end++;
            }
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
        for c in ref_path { out.push(c); }
        return;
    }
    var last_slash = -1;
    for i in base_path.len {
        if base_path[i] == '/' { last_slash = i; }
    }
    if last_slash >= 0 {
        for i in last_slash + 1 { out.push(base_path[i]); }
        for c in ref_path { out.push(c); }
    } else {
        for c in ref_path { out.push(c); }
    }
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
        for c in r.scheme { target_scheme.push(c); }
        target_has_authority = r.has_authority;
        for c in r.userinfo { target_userinfo.push(c); }
        for c in r.host { target_host.push(c); }
        target_port = r.port;
        remove_dot_segments(r.path, target_path);
        target_has_query = r.has_query;
        for c in r.query { target_query.push(c); }
    } else {
        if r.has_authority {
            target_has_authority = true;
            for c in r.userinfo { target_userinfo.push(c); }
            for c in r.host { target_host.push(c); }
            target_port = r.port;
            remove_dot_segments(r.path, target_path);
            target_has_query = r.has_query;
            for c in r.query { target_query.push(c); }
        } else {
            if r.path.len == 0 {
                for c in base.path { target_path.push(c); }
                if r.has_query {
                    target_has_query = true;
                    for c in r.query { target_query.push(c); }
                } else {
                    target_has_query = base.has_query;
                    for c in base.query { target_query.push(c); }
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
                for c in r.query { target_query.push(c); }
            }
            target_has_authority = base.has_authority;
            for c in base.userinfo { target_userinfo.push(c); }
            for c in base.host { target_host.push(c); }
            target_port = base.port;
        }
        for c in base.scheme { target_scheme.push(c); }
    }
    target_has_fragment = r.has_fragment;
    for c in r.fragment { target_fragment.push(c); }

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
// Query String Parsing & Formatting (application/x-www-form-urlencoded)
// -----------------------------------------------------------------------------

fn decode_query_component(input: const u8[:], out: u8[>..]&) -> bool {
    var i = 0;
    while i < input.len {
        let c = input[i];
        if c == '+' {
            out.push(' ');
            i++;
        } else if c == '%' {
            if i + 2 >= input.len { return false; }
            let h1 = input[i + 1];
            let h2 = input[i + 2];
            if !is_hex_digit(h1) || !is_hex_digit(h2) { return false; }
            out.push((hex_val(h1) << 4) | hex_val(h2));
            i += 3;
        } else {
            out.push(c);
            i++;
        }
    }
    return true;
}

fn encode_query_component(input: const u8[:], out: u8[>..]&) {
    for c in input {
        if is_unreserved(c) {
            out.push(c);
        } else if c == ' ' {
            out.push('+');
        } else {
            out.push('%');
            out.push(HEX_CHARS[(c >> 4) & 0x0F]);
            out.push(HEX_CHARS[c & 0x0F]);
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
