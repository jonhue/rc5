#include <err.h>
#include <sysexits.h>
#include "test.h"

static void save_roundkeys(uint16_t *saved_roundkeys);

static void restore_roundkeys(uint16_t *saved);

static int cmp_plain_to_decrypted(char *plain, char *key, uint32_t iv, uint16_t *savedRoundkeys);

static int cmp_to_RFC2040(char *plain, char *key, uint32_t iv, uint16_t *savedRoundkeys);

extern uint16_t *get_roundkeys_address();

void run_test(char *id) {
    // Speichern der vorgenerierten Rundenschlüssel,
    // damit diese später zurückgesetzt werden können.
    uint16_t *saved_roundkeys = (uint16_t *) malloc(34 * 2);
    if (saved_roundkeys == NULL) {
        err(EX_OSERR, NULL);
    }
    save_roundkeys(saved_roundkeys);

    if (id == NULL || strcmp(id, "rfc2040") == 0) {
        uint32_t iv = 0xabcd1234;
        char key[] = "thisisakey";
        char *plain = "This is going to be encrypted.";

        if (cmp_to_RFC2040(plain, key, iv, saved_roundkeys)) {
            printf("Test \"rfc2040\" passed: RFC2040 implementation gives the same output as ours for a small input.\n");
        } else {
            printf("Test \"rfc2040\" failed: RFC2040 implementation does not give the same output as ours for a small input.\n");
        }
    }
    if (id == NULL || strcmp(id, "cbc") == 0) {
        uint32_t iv = 0xabcd1234;
        char key[] = "thisisakey";
        int size = 1000000;
        char *plain = malloc(size);
        if (plain == NULL) {
            err(EX_OSERR, NULL);
        }

        *plain = 1;
        *(plain + 1) = 1;

        //Generate a million fibonacci numbers mod 255
        for (int i = 2; i < size; ++i) {
            *(plain + i) = *(plain + i - 1) + *(plain + i - 2);
        }

        if (cmp_plain_to_decrypted(plain, key, iv, saved_roundkeys)) {
            printf("Test \"cbc\" passed: The decrypted version equals the plaintext (~1MB) for the CBC mode.\n");
        } else {
            printf("Test \"cbc\" failed: The decrypted version does not equal the plaintext (~1MB) for the CBC mode.\n");
        }

        free(plain);
    }

    free(saved_roundkeys);
}

static void save_roundkeys(uint16_t *saved_roundkeys) {
    memcpy(saved_roundkeys, roundkeys, 34 * 2);
}

static void restore_roundkeys(uint16_t *saved) {
    memcpy(roundkeys, saved, 34 * 2);
}

void setup_RFC2040_testvector(test_vector *ptv, int padding, char *key, size_t key_length,
                              char *plain, int plain_length, uint32_t iv) {
    ptv->padding_mode = padding;
    ptv->rounds = 16;
    memcpy(ptv->key, key, key_length);
    ptv->key_length = strlen(key);
    memcpy(ptv->iv, (char *) &iv, 4);
    ptv->iv_length = 4;
    memcpy(ptv->plain, plain, plain_length);
    ptv->plain_length = plain_length;
}

static int cmp_plain_to_decrypted(char *plain, char *key, uint32_t iv, uint16_t *saved_roundkeys) {
    int size_plain = strlen(plain);
    int size_pad = BLOCKSIZE - (size_plain % BLOCKSIZE);
    int size_all = size_plain + size_pad;
    int keylen = strlen(key);

    char *data = malloc(size_all);
    if (data == NULL) {
        err(EX_OSERR, NULL);
    }

    memcpy(data, plain, size_plain);
    pkcs7_pad((uint8_t *) data + size_plain, size_pad);

    char *origin_key = malloc(keylen);
    if (origin_key == NULL) {
        err(EX_OSERR, NULL);
    }
    memcpy(origin_key, key, keylen);

    restore_roundkeys(saved_roundkeys);

    // Verschlüssele Plaintext + padding mit unserer Implementierung
    rc5_cbc_enc((unsigned char *) key, keylen, (uint32_t *) data, size_all, iv);

    restore_roundkeys(saved_roundkeys);

    // Entschlüssele Ciphertext mit unserer Implementierung
    rc5_cbc_dec((unsigned char *) origin_key, keylen, (uint32_t *) data, size_all, iv);

    // Vergleiche Plaintext mit Entschlüsseltem
    int result = memcmp(plain, data, size_plain) == 0;

    free(origin_key);
    free(data);

    return result;
}

static int cmp_to_RFC2040(char *plain, char *key, uint32_t iv, uint16_t *saved_roundkeys) {
    int size_plain = strlen(plain);
    int size_pad = BLOCKSIZE - (size_plain % BLOCKSIZE);
    int size_all = size_plain + size_pad;

    char *data_our = malloc(size_all);
    if (data_our == NULL) {
        err(EX_OSERR, NULL);
    }
    char *data_rfc = malloc(size_all);
    if (data_rfc == NULL) {
        err(EX_OSERR, NULL);
    }

    memcpy(data_our, plain, size_plain);

    pkcs7_pad((uint8_t *) data_our + size_plain, size_pad);

    memcpy(data_rfc, data_our, size_all);

    // Verschlüssele Plaintext + padding mit der RFC2040-Implementierung
    test_vector *ptv = malloc(sizeof(test_vector));
    if (ptv == NULL) {
        err(EX_OSERR, NULL);
    }
    setup_RFC2040_testvector(ptv, 1, key, strlen(key), data_rfc, size_all, iv);
    run_rfc2040_test(ptv, 1);

    restore_roundkeys(saved_roundkeys);

    // Verschlüssele Plaintext + padding mit unserer Implementierung
    rc5_cbc_enc((unsigned char *) key, strlen(key), (uint32_t *) data_our, size_all, iv);

    // Vergleiche die Ciphertexts
    int result = memcmp(ptv->cipher, data_our, size_all) == 0;

    free(ptv);
    free(data_our);
    free(data_rfc);

    return result;
}
