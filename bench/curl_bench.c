// SPDX-License-Identifier: Apache-2.0
// C benchmark using libcurl's curl_url API
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <curl/curl.h>

static inline double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

int main(int argc, char **argv) {
    long iterations = 100000;
    if (argc > 1) {
        iterations = atol(argv[1]);
        if (iterations <= 0) iterations = 100000;
    }

    const char *url_str = "https://user:pass@example.com:8443/api/v1/resource/items?filter=active&sort=desc#section-1";

    // 1. Bench Parse
    double start = get_time_sec();
    long checksum = 0;
    for (long i = 0; i < iterations; i++) {
        CURLU *uh = curl_url();
        CURLUcode rc = curl_url_set(uh, CURLUPART_URL, url_str, 0);
        if (rc == CURLUE_OK) {
            char *port = NULL;
            curl_url_get(uh, CURLUPART_PORT, &port, 0);
            if (port) {
                checksum += atoi(port);
                curl_free(port);
            }
        }
        curl_url_cleanup(uh);
    }
    double elapsed_parse = get_time_sec() - start;
    double parse_ops = iterations / elapsed_parse;
    double parse_ns = (elapsed_parse / iterations) * 1e9;
    printf("curl_url parse:       %ld ops in %.6f s (%.0f ops/sec, %.1f ns/op, checksum=%ld)\n",
           iterations, elapsed_parse, parse_ops, parse_ns, checksum);

    // 2. Bench Resolve
    const char *base_str = "http://a/b/c/d;p?q";
    const char *ref_str = "../../g?y#s";
    start = get_time_sec();
    long resolve_checksum = 0;
    for (long i = 0; i < iterations; i++) {
        CURLU *uh = curl_url();
        curl_url_set(uh, CURLUPART_URL, base_str, 0);
        curl_url_set(uh, CURLUPART_URL, ref_str, 0);
        char *path = NULL;
        curl_url_get(uh, CURLUPART_PATH, &path, 0);
        if (path) {
            resolve_checksum++;
            curl_free(path);
        }
        curl_url_cleanup(uh);
    }
    double elapsed_resolve = get_time_sec() - start;
    double resolve_ops = iterations / elapsed_resolve;
    double resolve_ns = (elapsed_resolve / iterations) * 1e9;
    printf("curl_url resolve:     %ld ops in %.6f s (%.0f ops/sec, %.1f ns/op, checksum=%ld)\n",
           iterations, elapsed_resolve, resolve_ops, resolve_ns, resolve_checksum);

    return 0;
}
