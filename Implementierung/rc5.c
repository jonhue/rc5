#include <string.h>
#include <getopt.h>
#include <sysexits.h>
#include <err.h>
#include "rc5.h"
#include "test.h"
#include "bufferio.h"
#include "perf.h"

extern void reset_registers();

static void lock(const void *addr, size_t len);

static int print_progress(size_t progress, size_t unit, int last_percentage);

void *data = NULL;
size_t size = -1;
int verbose = 0;

static void cleanup(void) {
    if (data != NULL) {
        if (size > 0) {
            memset(data, 0, size);
        }
        free(data);
        data = NULL;
    }
}

static void usage(const char *restrict program_name) {
    errx(EX_USAGE,
         "Usage: %s <command>\n\n"
         "    enc [-m <mode>] [-v] <key> <inputFile> [<outputFile>]\n"
         "    dec [-m <mode>] [-v] <key> <inputFile> [<outputFile>]\n"
         "    test [test_id]\n"
         "    perf\n\n"
         "where <mode> is one of:\n"
         "    cbc, ctr, ecb",
         program_name);
}

int main(int argc, char **argv) {
    atexit(&cleanup);
    char *program_name = argv[0];

    int encrypt = 0, decrypt = 0, mode = 0;

    int opt;
    while ((opt = getopt(argc, argv, "m:v")) != -1) {
        switch (opt) {
            case 'm':
                if (strcmp(optarg, "cbc") == 0) {
                    mode = 0;
                } else if (strcmp(optarg, "ctr") == 0) {
                    mode = 1;
                } else if (strcmp(optarg, "ecb") == 0) {
                    mode = 2;
                } else {
                    usage(program_name);
                }
                break;
            case 'v':
                verbose = 1;
                break;
            default:
                usage(program_name);
        }
    }

    // optind enthält den Index auf das nächste argv Argument
    argc -= optind;
    argv += optind;

    if (argc < 1) {
        // Kein Command
        usage(program_name);
    }

    if (strcmp(argv[0], "enc") == 0) {
        encrypt = 1;
    } else if (strcmp(argv[0], "dec") == 0) {
        decrypt = 1;
    } else if (strcmp(argv[0], "test") == 0) {
        if (argc == 0) {
            run_test(NULL);
        } else {
            run_test(argv[1]);
        }
        exit(EXIT_SUCCESS);
    } else if (strcmp(argv[0], "perf") == 0) {
        run_perf_tests();
        exit(EXIT_SUCCESS);
    } else {
        usage(program_name);
    }

    if (argc < 3 || argc > 4) {
        // Keine Input-Datei oder Schlüssel
        usage(program_name);
    }

    const char *restrict key = argv[1];
    lock(key, strlen(key)); // Key nicht in einen Swap speichern
    // Roundkeys werden später mit sensitven Daten überschrieben
    lock(&roundkeys, (2 * ROUNDS + 2) * 2);

    const char *restrict inputFile = argv[2];
    const char *restrict outputFile = argc == 4 ? argv[3] : argv[2];

    if(strlen(key) == 0) {
        errx(EX_DATAERR, "Key may not be empty. Aborting.");
    }

    size = read_file(inputFile, NULL, 0);
    if (size == -1u) {
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
            if (verbose) {
                printf("Using ECB mode for encryption...\n");
            }

            rc5_ecb_enc((unsigned char *) key, strlen(key), data, size);
        } else if (mode == 1) {
            if (verbose) {
                printf("Using CTR mode for encryption...\n");
            }

            rc5_ctr((unsigned char *) key, strlen(key), data, size);
        } else if (mode == 0) {
            if (verbose) {
                printf("Using CBC mode for encryption...\n");
            }

            uint32_t iv = arc4random(); // Initialisierungsvektor
            rc5_cbc_enc((unsigned char *) key, strlen(key), data, size_text + size_pad, iv);

            // Füge iv ans Dateiende an (nach padding)
            ((uint32_t *) data)[(size_text + size_pad) / sizeof(uint32_t)] = iv;
        }
    } else if (decrypt) {
        // Abbruch, falls die Länge des Ciphertextes kein Vielfaches der Blockgröße ist
        // oder die Datei zu klein ist (mindestens ein ganzer Block und der IV)
        if (size_text % BLOCKSIZE != 0 || size_text < 4 + size_iv) {
            errx(EX_DATAERR, "%s: Could not decrypt. File is malformed.", inputFile);
        }

        if (mode > 0) {
            if (mode == 2) {
                if (verbose) {
                    printf("Using ECB mode for decryption...\n");
                }

                rc5_ecb_dec((unsigned char *) key, strlen(key), data, size);
            } else if (mode == 1) {
                if (verbose) {
                    printf("Using CTR mode for decryption...\n");
                }

                rc5_ctr((unsigned char *) key, strlen(key), data, size);
            }
	    
            uint8_t size_padding = ((uint8_t *) data)[size - 1];
            if (size_padding > 4 || size_padding == 0) {
                errx(EX_DATAERR, "%s: Could not decrypt. File is malformed.", inputFile);
            }

            // reduziere size um Länge des Paddings
            size = size - size_padding;
        } else if (mode == 0) {
            if (verbose) {
                printf("Using CBC mode for decryption...\n");
            }

            // Initialisierungsvektor am Dateiende
            uint32_t iv = ((uint32_t *) data)[size / sizeof(uint32_t) - 1];

            rc5_cbc_dec((unsigned char *) key, strlen(key), data, size - size_iv, iv);

            uint8_t size_padding = ((uint8_t *) data)[size - size_iv - 1];
            if (size_padding > 4 || size_padding == 0) {
                errx(EX_DATAERR, "%s: Could not decrypt. File is malformed.", inputFile);
            }

            // reduziere size um Länge des Paddings und des Initialisierungsvektors
            size = size - size_iv - size_padding;
        }
    }

    if (verbose) {
        printf("\rWriting to file...");
        fflush(stdout);
    }
    if (write_file(outputFile, data, size)) {
        err(EX_IOERR, "%s", outputFile);
    }
    if (verbose) {
        printf("\rDone!             \n");
    }

    exit(EXIT_SUCCESS);
}

void pkcs7_pad(void *buf, size_t len) {
    for (unsigned int i = 0; i < len; i++) {
        ((uint8_t *) buf)[i] = len;
    }
}

void rc5_cbc_enc(unsigned char *key, size_t keylen, uint32_t *buffer, size_t len, uint32_t iv) {
    // allokiere Speicherbereich für L
    size_t l_len = keylen % 2 == 0 ? keylen : keylen + 1;
    void *l = malloc(l_len);
    lock(l, l_len);

    // Keysetup
    rc5_init(key, keylen, l);

    // benutze iv um den ersten block zu XORen
    *buffer ^= iv;
    rc5_enc(buffer);

    int progress = 0;
    for (size_t i = 1; i < len / BLOCKSIZE; i++) {
        uint32_t *lastblock = buffer++;
        *buffer ^= *lastblock;
        rc5_enc(buffer);

        if (verbose) {
            progress = print_progress(i, len / BLOCKSIZE, progress);
        }
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
    lock(l, l_len);

    // Keysetup
    rc5_init(key, keylen, l);

    uint32_t lastenc = *buffer;
    // benutze iv um den ersten block zu XORen
    rc5_dec(buffer);
    *buffer ^= iv;

    int progress = 0;
    for (size_t i = 1; i < len / BLOCKSIZE; i++) {
        uint32_t curenc = *(++buffer);
        rc5_dec(buffer);
        *buffer ^= lastenc;
        lastenc = curenc;

        if (verbose) {
            progress = print_progress(i, len / BLOCKSIZE, progress);
        }
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
    lock(l, l_len);

    // Keysetup
    rc5_init(key, keylen, l);

    size_t i = 0;
    int progress = 0;
    while (i < len / BLOCKSIZE) {
        if (i + 7 < len / BLOCKSIZE) {
            uint32_t encrypted_counters[8] = {i, i + 1, i + 2, i + 3, i + 4, i + 5, i + 6, i + 7};
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

        if (verbose) {
            progress = print_progress(i, len / BLOCKSIZE, progress);
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
    lock(l, l_len);

    // Keysetup
    rc5_init(key, keylen, l);

    size_t i = 0;
    int progress = 0;
    while (i < len / BLOCKSIZE) {
        if (i + 7 < len / BLOCKSIZE) {
            rc5_enc_128(buffer);
            buffer += 8;
            i += 8;
        } else {
            rc5_enc(buffer++);
            i++;
        }

        if (verbose) {
            progress = print_progress(i, len / BLOCKSIZE, progress);
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
    lock(l, l_len);

    // Keysetup
    rc5_init(key, keylen, l);

    int progress = 0;
    for (size_t i = 0; i < len / BLOCKSIZE; i++) {
        rc5_dec(buffer++);

        if (verbose) {
            progress = print_progress(i, len / BLOCKSIZE, progress);
        }
    }

    reset_registers();
    memset(l, 0, l_len);
    memset(key, 0, keylen);
    free(l);
}

static void lock(const void *addr, size_t len) {
#include <sys/mman.h>
    // Funktionen aus diesem Header, können nur in dieser Methode aufgerufen werden
    // Verhindert Aufruf von mlock ohne entsrpechende Warnung

    if (mlock(addr, len) && verbose) {
        warn("Could not lock memory. Sensitive data might be exposed on an unencrypted disk.");
    }
}

static int print_progress(size_t progress, size_t unit, int last_percentage) {
    int percentage = (100 * progress) / unit;
    if (percentage > last_percentage) {
        printf("\rIn progress %d%%", percentage);
        fflush(stdout);
    }

    return percentage;
}
