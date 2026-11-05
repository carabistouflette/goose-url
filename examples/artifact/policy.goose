// SPDX-License-Identifier: Apache-2.0
// Example-owned origin policy. This is not part of goose-url's core API.
namespace artifact_url;
import url;

const MAX_DOWNLOAD_URL_BYTES = 8192;

fn dns_host(host: const u8[:]) -> bool {
    if host.len < 1 || host.len > 253 { return false; }
    var label_start: i64 = 0;
    for c, i in host {
        if c == '.' {
            if i == label_start || i - label_start > 63 || host[label_start] == '-' || host[i - 1] == '-' { return false; }
            label_start = i + 1;
        } else if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' {
            return false;
        }
    }
    if label_start == host.len || host.len - label_start > 63 || host[label_start] < 'a' || host[label_start] > 'z' || host[host.len - 1] == '-' { return false; }
    return true;
}

fn allows(raw: const u8[:], trusted_host: const u8[:], trusted_port: i32) -> bool {
    if raw.len < 1 || raw.len > MAX_DOWNLOAD_URL_BYTES || trusted_port < 1 || trusted_port > 65535 { return false; }
    let view, error = url::parse_view(raw);
    if error.kind != url::ErrorKind.None || view.scheme != "https" || !view.has_authority ||
        view.has_userinfo || view.has_fragment || view.host != trusted_host { return false; }
    if view.host.len > 2 && view.host[0] == '[' {
        // parse_view already checked IPv6/IPvFuture syntax. Only IPv6 is allowed here.
        for c in view.host[1..view.host.len - 1] {
            if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && c != ':' && c != '.' { return false; }
        }
    } else if !dns_host(view.host) { return false; }
    if view.has_port {
        if view.port != trusted_port { return false; }
        // Accept canonical nonzero decimal ports, avoiding backend length limits.
        let start = 8 + view.host.len + 1;
        if start >= raw.len || raw[start] == '0' { return false; }
        var end = start;
        while end < raw.len && raw[end] >= '0' && raw[end] <= '9' { end++; }
        if end - start < 1 || end - start > 5 { return false; }
    } else if trusted_port != 443 { return false; }
    return true;
}

fn port(text: const u8[:]) -> i32 {
    if text.len < 1 || text.len > 5 || text[0] == '0' { return -1; }
    var value: i32 = 0;
    for c in text {
        if c < '0' || c > '9' { return -1; }
        value = value * 10 + (c - '0');
    }
    return if value > 0 && value <= 65535 { value } else { -1 };
}
