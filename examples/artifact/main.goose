// SPDX-License-Identifier: Apache-2.0
import url from "../..";
import .policy;
import artifact from "carabistouflette/goose-artifact@c2d190b613c541a5dba839ce380de8b111c9ab0c";
import crypto from "carabistouflette/goose-crypto@a4643f62bd5e76b371054c6537a95169a7930101";
import http from "carabistouflette/goose-http@aa915a0b21db1129f85e6e339a6f0171bcac0e77";
import fs from "carabistouflette/goose-fs@cd0bd29c78c435caaebf75bfecd8e3e2083636eb";
import json_codec from "carabistouflette/goose-json@3fa7b5275399641f8069698b6c097ea66cef7929";
import std;
import os;

fn limit(text: const u8[:]) -> i64 {
    if text.len < 1 || text.len > 10 { return -1; }
    var value: i64 = 0;
    for c in text {
        if c < '0' || c > '9' { return -1; }
        value = value * 10 + c - '0';
        if value > artifact::MAX_DOWNLOAD_BYTES { return -1; }
    }
    return value;
}

fn main() {
    let argv = args();
    if argv.len != 11 {
        write_stderr("usage: artifact METADATA SIGNATURE KEY URL TRUSTED_HOST TRUSTED_PORT PRIVATE_PARENT STAGING_LEAF FINAL_LEAF BYTE_LIMIT\n");
        exit(2);
    }
    // Host and port come from application configuration, never from the URL itself.
    if !artifact_url::allows(argv[4], argv[5], artifact_url::port(argv[6])) {
        write_stderr("artifact: stage=UrlPolicy\n");
        exit(1);
    }
    let bytes = limit(argv[10]);
    if bytes < 0 {
        write_stderr("artifact: stage=InputLimit\n");
        exit(1);
    }
    let request = artifact::Request { metadata_path: argv[1], signature_hex: argv[2],
        trusted_key_hex: argv[3], expected_url: argv[4], private_parent: argv[7],
        staging_leaf: argv[8], final_leaf: argv[9], byte_limit: bytes };
    let result = artifact::execute(request);
    let message = artifact::describe(result);
    if result.stage == artifact::Stage.None { print(message); }
    else { write_stderr(str(message, "\n")); }
    exit(if result.stage == artifact::Stage.None { 0 } else { 1 });
}
