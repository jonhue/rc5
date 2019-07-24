#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sysexits.h>
#include <err.h>
#include "bufferio.h"

#define BMP_HEADER_LENGTH 54

/**
 * Ersetzt den Header einer verschlüsselten BMP Datei mit einem unverschlüsselten Header, sodass
 * das verschlüsselte Bild dargestellt werden kann.
 */
int main(int argc, char **argv) {
    if (argc != 3) {
        printf("usage: %s <original_bmp> <encrypted_bmp>\n", argv[0]);
        return 1;
    }

    char *pathOrigin = argv[1];
    char *pathEnc = argv[2];

    size_t size_original = read_file(pathOrigin, NULL, 0);
    size_t size_enc = read_file(pathEnc, NULL, 0);
    if (size_original == -1u) {
        err(EX_IOERR, "%s", pathOrigin);
    }

    if (size_enc == -1u) {
        err(EX_IOERR, "%s", pathEnc);
    }

    if (size_enc <= size_original) {
        errx(EX_DATAERR, "One of the given files is malformed!");
    }

    void *origin = malloc(BMP_HEADER_LENGTH);
    if (origin == NULL) {
        err(EX_OSERR, NULL);
    }
    void *enc = malloc(size_original);
    if (enc == NULL) {
        err(EX_OSERR, NULL);
    }

    if (((uint32_t *) origin)[14] != 40 || // Nur Version 3
        ((uint16_t *) origin)[28] < 24 ||  // Keine Indizierung
        ((uint32_t *) origin)[30] != 0) { // keine Kompression
        printf("Only BMP version 3 without compression and indexed colors is supported\n");
    }

    if (read_file(pathOrigin, origin, BMP_HEADER_LENGTH)) {
        free(origin);
        free(enc);
        err(EX_IOERR, "%s", pathOrigin);
    }

    if (read_file(pathEnc, enc, size_original)) {
        free(origin);
        free(enc);
        err(EX_IOERR, "%s", pathEnc);
    }

    memcpy(enc, origin, BMP_HEADER_LENGTH);
    if (write_file(pathEnc, enc, size_original)) {
        printf("Could not write enc\n");
    }

    free(origin);
    free(enc);
    return 0;
}
