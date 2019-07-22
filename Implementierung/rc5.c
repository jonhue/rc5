#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <sysexits.h>
#include <err.h>
#include "rc5.h"

#define ROUNDS 16
#define BLOCKSIZE 4
#define HALFBLOCK BLOCKSIZE/2

void *data = NULL;
size_t size = -1;

void cleanup(void) {
    if (data != NULL) {
        if (size > 0) {
            memset(data, 0, size);
        }
        free(data);
        data = NULL;
    }
}

void usage(const char *restrict program_name) {
    errx(EX_USAGE,
         "Usage: %s <command>\n\n"
         "    %s enc <key> <inputFile> [outputFile] [-m <mode>]\n"
         "    %s dec <key> <inputFile> [outputFile] [-m <mode>]\n\n"
         "where <mode> is one of:\n"
         "    cbc, ctr, ecb",
         program_name, program_name, program_name);
}

int main(int argc, char **argv) {
    atexit(&cleanup);
    char *program_name = argv[0];

    int encrypt = 0, decrypt = 0, mode = 0;

    const struct option longopts[] = {
            {"encrypt", no_argument, NULL, 'e'}, // entweder --encrypt oder -e
            {"decrypt", no_argument, NULL, 'd'}, // entweder --decrypt oder -d
            {NULL,      no_argument, NULL, 0}
            // Aus der man page von getopt_long:
            // "The last element of the longopts array has to be filled with zeroes"
            // Ansonsten kann es bei nicht bekanntem Argument zu einem segmentation fault kommen
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "m:", longopts, NULL)) != -1) {
        switch (opt) {
            case 'm':
                if (strcmp(optarg, "cbc") == 0) {
                    mode = 0;
                } else if (strcmp(optarg, "ctr") == 0) {
                    mode = 1;
                } else if (strcmp(optarg, "ecb") == 0) {
                    mode = 2;
                } else {
                    mode = -1;
                }
                break;
        }
    }

    // optind enthält den Index auf das nächste argv Argument
    argc -= optind;
    argv += optind;

    if (argc < 3 || argc > 4) {
        // Keine input Datei oder Schlüssel
        usage(program_name);
    }

    if (strcmp(argv[0], "enc") == 0) {
        encrypt = 1;
    } else if (strcmp(argv[0], "dec") == 0) {
        decrypt = 1;
    } else {
        usage(program_name);
    }

    if (mode == 2)
        printf("Using ECB mode...\n");
    else if (mode == 1)
        printf("Using CTR mode...\n");
    else if (mode == 0)
        printf("Using CBC mode...\n");
    else
        usage(program_name);

    const char *restrict key = argv[1];
    const char *restrict inputFile = argv[2];
    const char *restrict outputFile = argc == 4 ? argv[3] : argv[2];

    size = read_file(inputFile, NULL, 0);
    if (size == -1) {
        // Fehler beim Öffnen oder Bestimmen der Dateigröße
        err(EX_IOERR, "%s", inputFile);
    }
    size_t size_text = size;
    size_t size_pad = BLOCKSIZE - (size % BLOCKSIZE);
    size_t size_iv = sizeof(uint32_t);

    // Erhöhe size, um padding und Initialisierungsvektor zu speichern
    if (encrypt) {
        if (mode > 0) {
            size = size + size_pad;
        } else if (mode == 0) {
            size = size + size_pad + size_iv;
        }
    }
    data = malloc(size);
    if (!data) {
        err(EX_OSERR, NULL);
    }

    if (read_file(inputFile, data, size_text)) {
        err(EX_IOERR, "%s", inputFile);
    }

    if (encrypt) {
        // Füge padding nach Dateiinhalt an
        pkcs7_pad((uint8_t *) data + size_text, size_pad);

        // Verschlüssele Dateiinhalt + padding
        if (mode == 2) {
            rc5_ecb_enc((unsigned char *) key, strlen(key), data, size);
        } else if (mode == 1) {
            rc5_ctr((unsigned char *) key, strlen(key), data, size);
        } else if (mode == 0) {
            uint32_t iv = arc4random(); // Initialisierungsvektor
            rc5_cbc_enc((unsigned char *) key, strlen(key), data, size_text + size_pad, iv);

            // Füge iv ans Dateiende an (nach padding)
            ((uint32_t *) data)[(size_text + size_pad) / sizeof(uint32_t)] = iv;
        }
    } else if (decrypt) {
        // Abbruch, falls die Länge des Ciphertextes kein Vielfaches der Blockgröße ist
        if (size_text % BLOCKSIZE != 0) {
            errx(EX_DATAERR, "%s: Could not decrypt. File is malformed.", inputFile);
        }

        if (mode > 0) {
            if (mode == 2) {
                rc5_ecb_dec((unsigned char *) key, strlen(key), data, size);
            } else if (mode == 1) {
                rc5_ctr((unsigned char *) key, strlen(key), data, size);
            }

            // reduziere size um Länge des Paddings
            size = size - ((uint8_t *) data)[size - 1];
        } else if (mode == 0) {
            uint32_t iv = ((uint32_t *) data)[size / sizeof(uint32_t) - 1]; // Initialisierungsvektor am Dateiende
            rc5_cbc_dec((unsigned char *) key, strlen(key), data, size - size_iv, iv);

            // reduziere size um Länge des Paddings und des Initialisierungsvektors
            size = size - size_iv - ((uint8_t *) data)[size - size_iv - 1];
        }
    }

    if (write_file(outputFile, data, size)) {
        err(EX_IOERR, "%s", outputFile);
    }

    exit(EXIT_SUCCESS);
}

/**
 * Liest die Datei in path in buffer. Falls buffer NULL ist, gibt die Funktion die Dateigröße
 * zurück.
 * @param path Der Pfad zur Datei, die gelesen werden soll.
 * @param buffer Der Buffer in dem die Datei gespeichert werden soll. Wenn NULL, gibt die Funktion
 * die Dateigröße in Bytes zurück.
 * @param size Die Größe des Buffers.
 * @return Gibt die Dateigröße in Bytes zurück wenn buffer NULL ist, ansonsten wird 0
 * zurückgegeben. Falls ein Fehler auftritt, wird -1 zurückgegeben.
 */
long read_file(const char *restrict path, void *restrict buffer, size_t size) {
    // Öffne Datei, r = read mode
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        return -1;
    }

    if (buffer == NULL) {
        // Springe zum Dateiende, um Dateigröße herauszufinden
        if (fseek(file, 0, SEEK_END)) {
            // Schließe Datei und behalte ursprünglichen errno
            fclose_keep_errno(file);
            return -1;
        }

        // "File position indicator" am Ende der Datei, ftell() gibt also Dateigröße in Bytes zurück
        size = ftell(file);
        if (size == -1) {
            fclose_keep_errno(file);
            return -1;
        }

        if (fclose(file)) {
            return -1;
        }

        return size;
    }

    // Lies kompletten Dateiinhalt in den allokierten Speicher
    if (fread(buffer, 1, size, file) != size) {
        fclose(file);
        // Setze errno manuell, da fread() errno nicht setzt
        errno = EIO;
        return -1;
    }

    return fclose(file);
}

/**
 * Speichert buffer an den angegeben Pfad.
 * @param path Der Pfad an den buffer gespeichert werden soll.
 * @param buffer Der Buffer, der die zu speichernden Daten enthält.
 * @param size Die Größe des Buffers
 * @return Gibt 0 zuück wenn erfolgreich, ansonsten -1.
 *
 */
int write_file(const char *restrict path, const void *restrict buffer, size_t size) {
    // Öffne Datei, w = write mode
    FILE *file = fopen(path, "w");
    if (file == NULL) {
        return -1;
    }

    // Schreibe den kompletten buffer in die Datei
    if (fwrite(buffer, 1, size, file) != size) {
        fclose(file);
        errno = EIO;
        return -1;
    }

    return fclose(file);
}

/**
 * Helfermethode, die eine Datei schließt und dabei den Wert von errno beibehält. Hilfreich falls
 * fclose(file) aufgrund eines vorangeganenen Fehlers aufgerufen werden soll, aber fclose nicht
 * den Fehlercode überschreiben soll, falls es auch in dieser zu einem Fehler kommt.
 *
 * @param file Die zu schließende Datei.
 */
void fclose_keep_errno(FILE *file) {
    int tmp = errno;
    fclose(file);
    errno = tmp;
}

void pkcs7_pad(void *buf, size_t len) {
    for (int i = 0; i < len; i++) {
        ((uint8_t *) buf)[i] = len;
    }
}

void rc5_cbc_enc(unsigned char *key, size_t keylen, uint32_t *buffer, size_t len, uint32_t iv) {
    // allokiere Speicherbereich für L
    size_t l_len = keylen % 2 == 0 ? keylen : keylen + 1;
    void *l = malloc(l_len);

    // Keysetup
    rc5_init(key, keylen, l);

    // benutze iv um den ersten block zu XORen
    *buffer ^= iv;
    rc5_enc(buffer);

    for (size_t i = 1; i < len / BLOCKSIZE; i++) {
        uint32_t *lastblock = buffer++;
        *buffer ^= *lastblock;
        rc5_enc(buffer);
    }

    reset_registers();
    memset(l, 0, l_len);
    memset(key, 0, keylen);
    free(l);
}

void rc5_cbc_dec(unsigned char *key, size_t keylen, uint32_t *buffer, size_t len, uint32_t iv) {
    // allokiere Speicherbereich für L
    size_t l_len = keylen % 2 == 0 ? keylen : keylen + 1;
    void *l = malloc(l_len);

    // Keysetup
    rc5_init(key, keylen, l);

    uint32_t lastenc = *buffer;
    // benutze iv um den ersten block zu XORen
    rc5_dec(buffer);
    *buffer ^= iv;

    for (size_t i = 1; i < len / BLOCKSIZE; i++) {
        uint32_t curenc = *(++buffer);
        rc5_dec(buffer);
        *buffer ^= lastenc;
        lastenc = curenc;
    }

    reset_registers();
    memset(l, 0, l_len);
    memset(key, 0, keylen);
    free(l);
}

void rc5_ctr(unsigned char *key, size_t keylen, uint32_t *buffer, size_t len) {
    // allokiere Speicherbereich für L
    size_t l_len = keylen % 2 == 0 ? keylen : keylen + 1;
    void *l = malloc(l_len);

    // Keysetup
    rc5_init(key, keylen, l);

    size_t i = 0;
    while (i < len / BLOCKSIZE) {
        if (i + 7 < len / BLOCKSIZE) {
            uint32_t encrypted_counters[8] = {i, i+1, i+2, i+3, i+4, i+5, i+6, i+7};
            rc5_enc_128(encrypted_counters);
            for (size_t j = 0; j < 8; j++) {
                *(buffer++) ^= encrypted_counters[j];
            }
            i += 8;
        } else {
            uint32_t encrypted_i = i;
            rc5_enc(&encrypted_i);
            *(buffer++) ^= encrypted_i;
            i++;
        }
    }

    reset_registers();
    memset(l, 0, l_len);
    memset(key, 0, keylen);
    free(l);
}

void rc5_ecb_enc(unsigned char *key, size_t keylen, uint32_t *buffer, size_t len) {
    // allokiere Speicherbereich für L
    size_t l_len = keylen % 2 == 0 ? keylen : keylen + 1;
    void *l = malloc(l_len);

    // Keysetup
    rc5_init(key, keylen, l);

    size_t i = 0;
    while (i < len / BLOCKSIZE) {
        if (i + 7 < len / BLOCKSIZE) {
            rc5_enc_128(buffer);
            buffer += 8; i += 8;
        } else {
            rc5_enc(buffer++);
            i++;
        }
    }

    reset_registers();
    memset(l, 0, l_len);
    memset(key, 0, keylen);
    free(l);
}

void rc5_ecb_dec(unsigned char *key, size_t keylen, uint32_t *buffer, size_t len) {
    // allokiere Speicherbereich für L
    size_t l_len = keylen % 2 == 0 ? keylen : keylen + 1;
    void *l = malloc(l_len);

    // Keysetup
    rc5_init(key, keylen, l);

    for (size_t i = 0; i < len / BLOCKSIZE; i++) {
        rc5_dec(buffer++);
    }

    reset_registers();
    memset(l, 0, l_len);
    memset(key, 0, keylen);
    free(l);
}
