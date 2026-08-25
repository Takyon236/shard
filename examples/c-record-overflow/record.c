/* A pocket-sized reader for a length-prefixed record, with one real defect.
 *
 * THE FORMAT
 *   line 1   the payload length, in decimal
 *   rest     the payload
 *
 * The defect is on the `memcpy` at the bottom: the destination is sized from what the file ACTUALLY
 * holds, and the copy length comes from what the file CLAIMS. Those are the same number in every
 * well-formed record, which is why this shape survives review and testing — every fixture anybody
 * writes by hand agrees with itself.
 *
 * Deliberately quiet on success. An entry point claiming `fatal_signal` needs nothing printed; a
 * program that chatters gives an adjudicator noise to mistake for evidence.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 2) {
        return 2;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        return 2;
    }

    /* An empty file has no header. Returning 0 here is what keeps the entry point's baseline quiet,
     * and the baseline is what makes a real observation mean something. */
    char header[32];
    if (!fgets(header, sizeof header, f)) {
        fclose(f);
        return 0;
    }

    long declared = strtol(header, NULL, 10);
    if (declared <= 0) {
        fclose(f);
        return 0;
    }

    char stage[512];

    /* Capped at the staging buffer, which is the kind of bound that makes this look handled. It bounds
     * the READ. It says nothing about the write below. */
    if (declared > (long) sizeof stage) {
        declared = (long) sizeof stage;
    }

    size_t got = fread(stage, 1, sizeof stage, f);
    fclose(f);

    char *buf = malloc(got ? got : 1);
    if (!buf) {
        return 2;
    }

    /* THE DEFECT. `got` bytes were allocated; `declared` bytes are copied. */
    memcpy(buf, stage, (size_t) declared);

    /* Read the result through a volatile so the optimiser cannot delete an allocate-copy-free chain
     * whose output nothing uses. Deliberately not PRINTED: this entry point claims `fatal_signal`,
     * and a program that chatters gives an adjudicator noise to mistake for evidence. */
    volatile char sink = buf[0];
    (void) sink;

    free(buf);
    return 0;
}
