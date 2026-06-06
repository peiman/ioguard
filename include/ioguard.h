#ifndef IOGUARD_H
#define IOGUARD_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * Scan text for prompt-injection and secret-leak indicators.
 *
 * # Arguments
 * - `text`: pointer to UTF-8 bytes (not necessarily NUL-terminated).
 * - `len`: number of bytes to read from `text`.
 * - `opts_json`: NUL-terminated JSON string for scan options, or NULL for defaults.
 *
 * # Returns
 * A heap-allocated NUL-terminated JSON string (Contract-A schema). Ownership
 * transfers to the caller, who **MUST** free it via [`ioguard_free`].
 *
 * Error conventions:
 * - NULL `text` → returns `{"error":"null input pointer"}` (caller must free)
 * - Invalid UTF-8 → returns `{"error":"invalid utf-8 input"}` (caller must free)
 * - Caught panic → returns NULL (nothing to free)
 * - Serialization failure → returns `{"error":"serialization failed"}` (caller must free)
 *
 * # Safety
 * - `text` must be NULL or point to at least `len` readable bytes.
 * - `opts_json` must be NULL or a valid pointer to a NUL-terminated C string.
 * - The returned pointer must be freed exactly once via [`ioguard_free`].
 */
char *ioguard_scan(const uint8_t *text,
                   size_t len,
                   const char *opts_json);

/**
 * Free a JSON string previously returned by [`ioguard_scan`].
 *
 * # Safety
 * - `json` must be NULL or a pointer previously returned by [`ioguard_scan`].
 * - Each non-NULL pointer must be freed exactly once.
 */
void ioguard_free(char *json);

#endif  /* IOGUARD_H */
