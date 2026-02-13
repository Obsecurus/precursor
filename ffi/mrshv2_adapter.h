#ifndef PRECURSOR_MRSHV2_ADAPTER_H
#define PRECURSOR_MRSHV2_ADAPTER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Hash payload bytes into a stable digest string.
 * Returns 0 on success and writes a heap-allocated C string to out_digest.
 * Caller must release out_digest with precursor_mrshv2_free.
 */
int precursor_mrshv2_hash(const uint8_t *payload, size_t payload_len, char **out_digest);

/*
 * Compute a normalized distance [0,100] between two digest strings.
 * 0 means identical and higher values are less similar.
 * Returns 0 on success.
 */
int precursor_mrshv2_diff(
    const char *left_digest,
    const char *right_digest,
    int *out_distance
);

/* Free heap-allocated digest strings returned by precursor_mrshv2_hash. */
void precursor_mrshv2_free(char *value);

/*
 * Return a pointer to thread-local error text for the last failure.
 * The returned pointer is borrowed and must not be freed.
 */
const char *precursor_mrshv2_last_error(void);

#ifdef __cplusplus
}
#endif

#endif
