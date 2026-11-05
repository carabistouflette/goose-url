/* SPDX-License-Identifier: Apache-2.0 */
/* Adapted from goose-artifact c2d190b tests/transport.c (Apache-2.0).
 * Fixture only: trust one local CA without disabling TLS verification. */
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
CURLMcode __real_curl_multi_add_handle(CURLM *, CURL *);
CURLMcode __wrap_curl_multi_add_handle(CURLM *multi, CURL *easy) {
    const char *expected = getenv("GOOSE_URL_FIXTURE_URL");
    const char *ca = getenv("GOOSE_URL_FIXTURE_CA");
    char *actual = NULL;
    if (!expected || !ca || strncmp(expected, "https://localhost:", 18) != 0 ||
        curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &actual) != CURLE_OK ||
        !actual || strcmp(actual, expected) != 0) {
        fputs("URL fixture rejected unexpected URL\n", stderr); exit(90);
    }
    if (curl_easy_setopt(easy, CURLOPT_CAINFO, ca) != CURLE_OK) {
        fputs("URL fixture CA setup failed\n", stderr); exit(90);
    }
    return __real_curl_multi_add_handle(multi, easy);
}
