// SPDX-License-Identifier: Apache-2.0
import url from "../..";
import .policy;
import std;
import os;
fn main() {
    let argv = args();
    if argv.len != 4 { exit(2); }
    print(if artifact_url::allows(argv[1], argv[2], artifact_url::port(argv[3])) { "1" } else { "0" });
}
