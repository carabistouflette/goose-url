/* SPDX-License-Identifier: Apache-2.0 */
/* Test-only, no-network authority oracle using the download backend parser. */
#include <curl/curl.h>
#include <stdio.h>
static void string(const char *s) {
    putchar('"');
    if (s) for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        if (*p == '"' || *p == '\\') printf("\\%c", *p);
        else if (*p < 32 || *p >= 127) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}
int main(int argc, char **argv) {
    if (argc < 2 || curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) return 2;
    for (int i = 1; i < argc; ++i) {
        CURLU *u = curl_url();
        if (!u) return 2;
        CURLUcode result = curl_url_set(u, CURLUPART_URL, argv[i], CURLU_DISALLOW_USER);
        char *scheme = NULL, *host = NULL, *port = NULL;
        if (result == CURLUE_OK) {
            result = curl_url_get(u, CURLUPART_SCHEME, &scheme, 0);
            if (result == CURLUE_OK) result = curl_url_get(u, CURLUPART_HOST, &host, 0);
            if (result == CURLUE_OK) result = curl_url_get(u, CURLUPART_PORT, &port, CURLU_DEFAULT_PORT);
        }
        printf("{\"status\":%u,\"scheme\":", (unsigned)result); string(scheme);
        fputs(",\"host\":", stdout); string(host);
        fputs(",\"port\":", stdout); string(port); puts("}");
        curl_free(scheme); curl_free(host); curl_free(port); curl_url_cleanup(u);
    }
    curl_global_cleanup();
    return ferror(stdout) ? 2 : 0;
}
