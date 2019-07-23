#include "test.h"

static uint16_t* save_roundkeys();

static void restore_roundkeys(uint16_t* saved);

static test_vector* setup_RFC2040_testvector(char* key, size_t key_length, char* plain, int plain_length, uint32_t iv);

static int cmp_plain_to_decrypted(char* plain, char* key, uint32_t iv, uint16_t* savedRoundkeys);

static int cmp_to_RFC2040(char* plain, char* key, uint32_t iv, uint16_t* savedRoundkeys);

extern uint16_t* get_roundkeys_address();

void run_test(char *id) {
    // Speichern der vorgenerierten Rundenschlüssel,
    // damit diese später zurückgesetzt werden können.
    uint16_t* savedRoundkeys = save_roundkeys();

    if(id == NULL || strcmp(id, "rfc2040") == 0) {
        uint32_t iv = 0xabcd1234;
        char key[] = "thisisakey";
        char* plain = "This is going to be encrypted.";

        if(cmp_to_RFC2040(plain, key, iv, savedRoundkeys)) {
            printf("Test \"rfc2040\" passed: RFC2040 implementation gives the same output as ours for a small input.\n");
        } else {
            printf("Test \"rfc2040\" failed: RFC2040 implementation does not give the same output as ours for a small input.\n");
        }
    }
    if(id == NULL || strcmp(id, "cbc") == 0) {
        uint32_t iv = 0xabcd1234;
        char key[] = "thisisakey";
        int size = 1000000;
        char* plain = malloc(size);

        *plain = 1;
        *(plain + 1) = 1;

        //Generate a million fibonacci numbers mod 255
        for(int i = 2; i < size; ++i) {
            *(plain + i) = *(plain + i - 1) + *(plain + i - 2);
        }

        if(cmp_plain_to_decrypted(plain, key, iv, savedRoundkeys)) {
            printf("Test \"cbc\" passed: The decrypted version equals the plaintext (~1MB) for the CBC mode.\n");
        } else {
            printf("Test \"cbc\" failed: The decrypted version does not equal the plaintext (~1MB) for the CBC mode.\n");
        }
    }
}

static uint16_t* save_roundkeys() {
    uint16_t* saved = (uint16_t*) malloc(34 * 2);
    memcpy(saved, get_roundkeys_address(), 34 * 2);
    return saved;
}

static void restore_roundkeys(uint16_t* saved) {
    memcpy(get_roundkeys_address(), saved, 34 * 2);
}

static test_vector* setup_RFC2040_testvector(char* key, size_t key_length, char* plain, int plain_length, uint32_t iv) {
    test_vector* ptv = (test_vector *) malloc(sizeof(*ptv));

    ptv->padding_mode = 1;
    ptv->rounds = 16;
    memcpy(ptv->key, key, key_length);
    ptv->key_length = strlen(key);
    memcpy(ptv->iv, (char*) &iv, 4);
    ptv->iv_length = 4;
    memcpy(ptv->plain, plain, plain_length);
    ptv->plain_length = plain_length;

    return ptv;
}

static int cmp_plain_to_decrypted(char* plain, char* key, uint32_t iv, uint16_t* savedRoundkeys) {
    int size_plain = strlen(plain);
    int size_pad = BLOCKSIZE - (size_plain % BLOCKSIZE);
    int size_all = size_plain + size_pad;
    int keylen = strlen(key);

    char* data = malloc(size_all);

    memcpy(data, plain, size_plain);
    pkcs7_pad((uint8_t *) data + size_plain, size_pad);

    char* orig_key = malloc(keylen);
    memcpy(orig_key, key, keylen);

    restore_roundkeys(savedRoundkeys);

    // Verschlüssele Plaintext + padding mit unserer Implementierung
    rc5_cbc_enc((unsigned char *) key, keylen, (uint32_t*) data, size_all, iv);

    restore_roundkeys(savedRoundkeys);

    // Entschlüssele Ciphertext mit unserer Implementierung
    rc5_cbc_dec((unsigned char *) orig_key, keylen, (uint32_t*) data, size_all, iv);

    // Vergleiche Plaintext mit Entschlüsseltem
    return memcmp(plain, data, size_plain) == 0;
}

static int cmp_to_RFC2040(char* plain, char* key, uint32_t iv, uint16_t* savedRoundkeys) {
    int size_plain = strlen(plain);
    int size_pad = BLOCKSIZE - (size_plain % BLOCKSIZE);
    int size_all = size_plain + size_pad;

    char* dataOur = malloc(size_all);
    char* dataRfc = malloc(size_all);

    memcpy(dataOur, plain, size_plain);
    memcpy(dataRfc, plain, size_plain);

    // Padding für unsere Implementierung, RFC2040 macht das selbst.
    pkcs7_pad((uint8_t *) dataOur + size_plain, size_pad);

    // Verschlüssele Plaintext + padding mit der RFC2040-Implementierung
    test_vector* ptv = setup_RFC2040_testvector(key, strlen(key), dataRfc, size_plain, iv);
    run_rfc2040_test(ptv);

    restore_roundkeys(savedRoundkeys);

    // Verschlüssele Plaintext + padding mit unserer Implementierung
    rc5_cbc_enc((unsigned char *) key, strlen(key), (uint32_t*) dataOur, size_all, iv);

    // Vergleiche die Ciphertexts
    return memcmp(ptv->cipher, dataOur, size_all) == 0;
}
