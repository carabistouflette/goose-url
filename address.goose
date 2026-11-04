// SPDX-License-Identifier: Apache-2.0
// RFC 3986 IP-literal syntax only; no DNS, zone identifiers or network policy.
namespace url_address;

fn hex(c: u8) -> bool {
    (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

fn future_char(c: u8) -> bool {
    (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
    c == '-' || c == '.' || c == '_' || c == '~' || c == '!' || c == '$' ||
    c == '&' || c == '\'' || c == '(' || c == ')' || c == '*' || c == '+' ||
    c == ',' || c == ';' || c == '=' || c == ':'
}

fn valid_ipv4(input: const u8[:]) -> bool {
    var at = 0;
    for part in 4 {
        let start = at;
        var value = 0;
        while at < input.len && input[at] != '.' {
            let c = input[at];
            if c < '0' || c > '9' || at - start >= 3 { return false; }
            value = value * 10 + c - '0';
            at++;
        }
        if at == start || value > 255 || (at - start > 1 && input[start] == '0') { return false; }
        if part < 3 {
            if at == input.len { return false; }
            at++;
        } else if at != input.len { return false; }
    }
    return true;
}

fn valid_literal(inner: const u8[:]) -> bool {
    if inner.len == 0 { return false; }
    if inner[0] == 'v' || inner[0] == 'V' {
        var at = 1;
        while at < inner.len && hex(inner[at]) { at++; }
        if at == 1 || at == inner.len || inner[at] != '.' { return false; }
        at++;
        if at == inner.len { return false; }
        while at < inner.len {
            if !future_char(inner[at]) { return false; }
            at++;
        }
        return true;
    }
    // Six full h16 groups and a dotted IPv4 tail need at most 45 bytes.
    if inner.len > 45 { return false; }
    var at = 0;
    var compressed = false;
    var groups = 0;
    if inner[0] == ':' {
        if inner.len < 2 || inner[1] != ':' { return false; }
        compressed = true;
        at = 2;
        if at == inner.len { return true; }
    }
    while at < inner.len {
        let start = at;
        var dotted = false;
        while at < inner.len && inner[at] != ':' {
            if inner[at] == '.' { dotted = true; }
            at++;
        }
        if at == start { return false; }
        if dotted {
            if at != inner.len || !valid_ipv4(inner[start..at]) { return false; }
            groups += 2;
        } else {
            if at - start > 4 { return false; }
            for c in inner[start..at] { if !hex(c) { return false; } }
            groups++;
        }
        if groups > 8 { return false; }
        if at == inner.len { break; }
        at++;
        if at == inner.len { return false; }
        if inner[at] == ':' {
            if compressed { return false; }
            compressed = true;
            at++;
            if at == inner.len { break; }
        }
    }
    return if compressed { groups < 8 } else { groups == 8 };
}
