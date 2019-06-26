#define ROUNDS 16
#define BLOCKSIZE 4
#define HALFBLOCK BLOCKSIZE/2

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

void pkcs7_pad(void *buf, size_t len);

void rc5_cbc_enc(unsigned char *key, size_t keylen, uint32_t *buffer, size_t len, uint32_t iv);

int rc5_cbc_dec(unsigned char *key, size_t keylen, uint32_t *buffer, size_t len, uint32_t iv);

extern void rc5_init(unsigned char *key, size_t keylen, void *s, void *l);

extern void rc5_enc(uint16_t *buffer, void *s);

extern void rc5_dec(uint16_t *buffer, void *s);

int main() {
    return 0;
}

void pkcs7_pad(void *buf, size_t len) {

}

void rc5_cbc_enc(unsigned char *key, size_t keylen, uint32_t *buffer, size_t len, uint32_t iv) {
    void *roundkeys;
    void *l;
    uint32_t *padbuf;
    uint32_t *curblock, *lastblock;
    size_t block_count, i;
    // allokiere Speicherbereich für die Rundenschluessel
    // 2r+2 Schluessel zu je 16 Bit laenge
    roundkeys = malloc((2 * ROUNDS + 2) * HALFBLOCK);
    l = malloc((2 * ROUNDS + 2) * HALFBLOCK);

    // Keysetup
    rc5_init(key, keylen, roundkeys, l);

    // allokiere Platz fuer das padding
    padbuf = (uint32_t *) malloc(len + (len % BLOCKSIZE));
    memcpy(padbuf, buffer, len);
    block_count = sizeof(padbuf) / BLOCKSIZE;

    pkcs7_pad((padbuf + (block_count - 1)), BLOCKSIZE - (len % BLOCKSIZE));


    // benutze einen initialization vector
    // um den ersten block zu XORen
    *padbuf ^= iv;
    rc5_enc((uint16_t *) padbuf, roundkeys);
    curblock = padbuf;
    for (i = 1; i < block_count; i++) {
        lastblock = curblock++;
        *curblock ^= *lastblock;
        rc5_enc(curblock, roundkeys);
    }
    free(roundkeys);
    free(l);
}

int rc5_cbc_dec(unsigned char *key, size_t keylen, uint32_t *buffer, size_t len, uint32_t iv) {
    void *roundkeys;
    void *l;
    uint32_t *padbuf;
    uint32_t *curblock, *lastblock;
    uint32_t lastenc, curenc;
    size_t block_count, i;
    // allokiere Speicherbereich für die Rundenschluessel
    // 2r+2 Schluessel zu je 16 Bit laenge
    roundkeys = malloc((2 * ROUNDS + 2) * HALFBLOCK);
    l = malloc((2 * ROUNDS + 2) * HALFBLOCK);

    // Keysetup
    rc5_init(key, keylen, roundkeys, l);

    if (len % BLOCKSIZE != 0)
        return -1; // error

    block_count = len / BLOCKSIZE;
    lastenc = *buffer;
    rc5_dec((uint16_t *) buffer, roundkeys);
    *buffer ^= iv;

    // benutze einen initialization vector
    // um den ersten block zu XORen
    for (i = 1; i < block_count; i++) {
        curenc = *++buffer;
        rc5_dec(buffer, roundkeys);
        *buffer ^= lastenc;
        lastenc = curenc;
    }
    free(roundkeys);
    // gibt laenge ohne padding zurueck
    return len - (*buffer & 0xFF);
}
