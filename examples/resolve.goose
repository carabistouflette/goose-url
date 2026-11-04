// SPDX-License-Identifier: Apache-2.0
// Example: Parsing URLs, resolving relative references, and building query strings.
import std;
import url from "..";

fn main() {
    let base, err = url::parse("https://api.github.com/repos/aardappel/goose/commits");
    assert(err.kind == url::ErrorKind.None);

    // Resolve relative path
    let commit_url, err2 = url::resolve(base, "eadca409f68210893f366e60d0c2f0dc29a339be?per_page=1#diff");
    assert(err2.kind == url::ErrorKind.None);
    print("Resolved URL: ", url::to_string(commit_url));

    // Parse and manipulate query
    let params = url::parse_query(commit_url.query);
    print("Query parameters count: ", params.len);
    for p, i in params {
        print("  [", i, "] ", p.key, " = ", p.value);
    }
}
