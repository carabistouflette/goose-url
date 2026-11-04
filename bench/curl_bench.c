// SPDX-License-Identifier: Apache-2.0
// Optional fixed-input workload using libcurl's owned CURLU representation.
#include <curl/curl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double time_sec(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        perror("clock_gettime");
        exit(1);
    }
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static int parse_once(const char *input) {
    CURLU *url = curl_url();
    char *port = NULL, *path = NULL;
    int ok = url && curl_url_set(url, CURLUPART_URL, input, 0) == CURLUE_OK &&
        curl_url_get(url, CURLUPART_PORT, &port, 0) == CURLUE_OK &&
        curl_url_get(url, CURLUPART_PATH, &path, 0) == CURLUE_OK &&
        strcmp(port, "8443") == 0 && strcmp(path, "/api/v1/resource/items") == 0;
    curl_free(port);
    curl_free(path);
    if (url) curl_url_cleanup(url);
    return ok;
}

static int resolve_once(const char *base, const char *reference) {
    CURLU *url = curl_url();
    char *path = NULL, *serialized = NULL;
    int ok = url && curl_url_set(url, CURLUPART_URL, base, 0) == CURLUE_OK &&
        curl_url_set(url, CURLUPART_URL, reference, 0) == CURLUE_OK &&
        curl_url_get(url, CURLUPART_PATH, &path, 0) == CURLUE_OK &&
        curl_url_get(url, CURLUPART_URL, &serialized, 0) == CURLUE_OK &&
        strcmp(path, "/g") == 0 && strcmp(serialized, "http://a/g?y#s") == 0;
    curl_free(path);
    curl_free(serialized);
    if (url) curl_url_cleanup(url);
    return ok;
}

static void print_result(const char *name, long iterations, double elapsed, long checksum) {
    if (elapsed <= 0) {
        fprintf(stderr, "invalid elapsed duration\n");
        exit(1);
    }
    printf("curl_url %s: %ld ops in %.9f s (%.0f ops/sec, %.1f ns/op, checksum=%ld)\n",
           name, iterations, elapsed, iterations / elapsed, elapsed * 1e9 / iterations, checksum);
}

int main(int argc, char **argv) {
    long iterations = 100000;
    if (argc > 2) return 2;
    if (argc == 2) {
        char *end = NULL;
        errno = 0;
        iterations = strtol(argv[1], &end, 10);
        if (errno || !argv[1][0] || *end || iterations < 1 || iterations > 10000000) return 2;
    }
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) return 1;
    const char *input = "https://user:pass@example.com:8443/api/v1/resource/items?filter=active&sort=desc#section-1";
    double start = time_sec();
    long checksum = 0;
    for (long i = 0; i < iterations; ++i) {
        if (!parse_once(input)) {
            fprintf(stderr, "curl URL parse did not produce expected fields\n");
            curl_global_cleanup();
            return 1;
        }
        checksum += 8443;
    }
    print_result("parse", iterations, time_sec() - start, checksum);
    start = time_sec();
    checksum = 0;
    for (long i = 0; i < iterations; ++i) {
        if (!resolve_once("http://a/b/c/d;p?q", "../../g?y#s")) {
            fprintf(stderr, "curl URL resolution did not produce expected URL/path\n");
            curl_global_cleanup();
            return 1;
        }
        ++checksum;
    }
    print_result("resolve", iterations, time_sec() - start, checksum);
    curl_global_cleanup();
    return 0;
}
