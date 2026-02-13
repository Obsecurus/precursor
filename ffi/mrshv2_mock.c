#include "mrshv2_adapter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static _Thread_local char g_last_error[256];

static void set_last_error(const char *message) {
    if (message == NULL) {
        g_last_error[0] = '\0';
        return;
    }
    snprintf(g_last_error, sizeof(g_last_error), "%s", message);
}

const char *precursor_mrshv2_last_error(void) {
    return g_last_error;
}

void precursor_mrshv2_free(char *value) {
    free(value);
}

int precursor_mrshv2_hash(const uint8_t *payload, size_t payload_len, char **out_digest) {
    if (payload == NULL || payload_len == 0 || out_digest == NULL) {
        set_last_error("invalid hash input");
        return -1;
    }

    /* Mock FNV-1a digest for CI/smoke tests. */
    unsigned long long hash = 1469598103934665603ULL;
    for (size_t i = 0; i < payload_len; i++) {
        hash ^= (unsigned long long)payload[i];
        hash *= 1099511628211ULL;
    }

    char *digest = (char *)malloc(64);
    if (digest == NULL) {
        set_last_error("unable to allocate digest buffer");
        return -1;
    }
    snprintf(digest, 64, "mrshv2:%zu:%016llx", payload_len, hash);
    *out_digest = digest;
    set_last_error("");
    return 0;
}

int precursor_mrshv2_diff(
    const char *left_digest,
    const char *right_digest,
    int *out_distance
) {
    if (left_digest == NULL || right_digest == NULL || out_distance == NULL) {
        set_last_error("invalid diff input");
        return -1;
    }

    size_t left_len = strlen(left_digest);
    size_t right_len = strlen(right_digest);
    size_t max_len = left_len > right_len ? left_len : right_len;
    if (max_len == 0) {
        *out_distance = 0;
        set_last_error("");
        return 0;
    }

    size_t min_len = left_len < right_len ? left_len : right_len;
    size_t mismatch = left_len > right_len ? left_len - right_len : right_len - left_len;
    for (size_t i = 0; i < min_len; i++) {
        if (left_digest[i] != right_digest[i]) {
            mismatch += 1;
        }
    }

    int distance = (int)((mismatch * 100 + (max_len / 2)) / max_len);
    if (distance < 0) {
        distance = 0;
    }
    if (distance > 100) {
        distance = 100;
    }
    *out_distance = distance;
    set_last_error("");
    return 0;
}
