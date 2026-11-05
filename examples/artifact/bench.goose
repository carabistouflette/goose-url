// SPDX-License-Identifier: Apache-2.0
import url from "../..";
import .policy;
import std;
import os;

fn main() {
    let argv = args();
    if argv.len != 3 || (argv[1] != "parse" && argv[1] != "policy") { exit(2); }
    var count: i64 = 0;
    if argv[2].len < 1 || argv[2].len > 7 { exit(2); }
    for c in argv[2] {
        if c < '0' || c > '9' { exit(2); }
        count = count * 10 + c - '0';
    }
    if count < 4 || count > 1000000 || count % 4 != 0 { exit(2); }
    let targets = ["https://downloads.example.org/a?x=1", "https://downloads.example.org:443/a%2Fb",
        "https://elsewhere.example.org/x", "https://downloads.example.org/#"];
    var checksum: i64 = 0;
    let start = clock();
    if argv[1] == "policy" {
        for i in count {
            if artifact_url::allows(targets[i % 4], "downloads.example.org", 443) { checksum++; }
        }
        assert(checksum == count / 2);
    } else {
        for i in count {
            let view, error = url::parse_view(targets[i % 4]);
            if error.kind == url::ErrorKind.None && view.has_authority { checksum++; }
        }
        assert(checksum == count);
    }
    let elapsed = clock() - start;
    assert(elapsed > 0.0);
    print("{\"seconds\":", elapsed, ",\"iterations\":", count, ",\"checksum\":", checksum, "}");
}
