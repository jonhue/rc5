#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

/* An RC5 context needs to know how many rounds it has, and its subkeys. */
typedef struct
{
    uint16_t *xk;
    int nr;
} rc5_ctx;

#define BLOCK 4
#define HALFBLOCK 2
#define HALFBLOCKBITS 16
/* Where possible, these should be replaced with actual rotate instructions.
 For Turbo C++, this is done with _lrotl and _lrotr. */
#define ROTL16(X, C) ((((uint16_t) (X)) << (C)) | (((uint16_t) (X)) >> (HALFBLOCKBITS - (C))))
#define ROTR16(X, C) ((((uint16_t) (X)) >> (C)) | (((uint16_t) (X)) << (HALFBLOCKBITS - (C))))
/* Function prototypes for dealing with RC5 basic operations. */
void rc5_init(rc5_ctx *, int);
void rc5_destroy(rc5_ctx *);
void rc5_key(rc5_ctx *, uint8_t *, int);
void rc5_encrypt(rc5_ctx *, uint16_t *, int);
void rc5_decrypt(rc5_ctx *, uint16_t *, int);
/* Function implementations for RC5. */
/* Scrub out all sensitive values. */
void rc5_destroy(rc5_ctx *c)
{
    int i;
    for (i = 0; i < (c->nr) * 2 + 2; i++)
    {
        c->xk[i] = 0;
    }
    free(c->xk);
}
/* Allocate memory for rc5 context’s xk and such. */
void rc5_init(rc5_ctx *c, int rounds)
{
    c->nr = rounds;
    c->xk = (uint16_t *) malloc(HALFBLOCK * (rounds * 2 + 2));
}
void rc5_encrypt(rc5_ctx *c, uint16_t *data, int blocks)
{
    uint16_t *d, *sk;
    int h, i, rc;
    d = data;
    sk = (c->xk) + 2;
    for (h = 0; h < blocks; h++)
    {
        d[0] += c->xk[0];
        d[1] += c->xk[1];
        for (i = 0; i < c->nr * 2; i += 2)
        {
            d[0] ^= d[1];
            rc = d[1] & (HALFBLOCKBITS - 1);
            d[0] = ROTL16(d[0], rc);
            d[0] += sk[i];
            d[1] ^= d[0];
            rc = d[0] & (HALFBLOCKBITS - 1);
            d[1] = ROTL16(d[1], rc);
            d[1] += sk[i + 1];
            /*printf(“Round %03d : %08lx %08lx sk= %08lx %08lx\n”,i/2,
 d[0],d[1],sk[i],sk[i+1]);*/
        }
        d += 2;
    }
}

void rc5_decrypt(rc5_ctx *c, uint16_t *data, int blocks)
{
    uint16_t *d, *sk;
    int h, i, rc;
    d = data;
    sk = (c->xk) + 2;
    for (h = 0; h < blocks; h++)
    {
        for (i = c->nr * 2 - 2; i >= 0; i -= 2)
        {
            /*printf(“Round %03d: %08lx %08lx sk: %08lx %08lx\n”,
 i/2,d[0],d[1],sk[i],sk[i+1]); */
            d[1] -= sk[i + 1];
            rc = d[0] & (HALFBLOCKBITS - 1);
            d[1] = ROTR16(d[1], rc);
            d[1] ^= d[0];
            d[0] -= sk[i];
            rc = d[1] & (HALFBLOCKBITS - 1);
            d[0] = ROTR16(d[0], rc);
            d[0] ^= d[1];
        }
        d[0] -= c->xk[0];
        d[1] -= c->xk[1];
        d += 2;
    }
}

void rc5_key(rc5_ctx *c, uint8_t *key, int keylen)
{
    uint16_t *pk, A, B; /* padded key */
    int xk_len, pk_len, i, num_steps, rc;
    uint8_t *cp;
    xk_len = c->nr * 2 + 2;
    pk_len = keylen / 2;
    if ((keylen % 2) != 0)
        pk_len += 1;
    pk = (uint16_t *)malloc(pk_len * 2);
    if (pk == NULL)
    {
        printf("An error occurred!\n");
        exit(-1);
    }
    /* Initialize pk –– this should work on Intel machines, anyway.... */
    for (i = 0; i < pk_len; i++)
        pk[i] = 0;
    cp = (uint8_t *)pk;
    for (i = 0; i < keylen; i++)
        cp[i] = key[i];
    /* Initialize xk. */
    c->xk[0] = 0xb7e1; /* P16 */
    for (i = 1; i < xk_len; i++)
        c->xk[i] = c->xk[i - 1] + 0x9e37; /* Q16 */
    /* TESTING */
    A = B = 0;
    for (i = 0; i < xk_len; i++)
    {
        A = A + c->xk[i];
        B = B ^ c->xk[i];
    }
    /* Expand key into xk. */
    if (pk_len > xk_len)
        num_steps = 3 * pk_len;
    else
        num_steps = 3 * xk_len;
    A = B = 0;
    for (i = 0; i < num_steps; i++)
    {
        A = c->xk[i % xk_len] = ROTL16(c->xk[i % xk_len] + A + B, 3);
        rc = (A + B) & (HALFBLOCKBITS - 1);
        B = pk[i % pk_len] = ROTL16(pk[i % pk_len] + A + B, rc);
    }
    /* Clobber sensitive data before deallocating memory. */
    for (i = 0; i < pk_len; i++)
        pk[i] = 0;
    free(pk);
}

int main(void)
{
    rc5_ctx c;
    uint16_t data[8];
    unsigned char key[] = "abcd";
    uint16_t i;
    
    /*for (i = 0; i < 8; i++)
        data[i] = i;*/
    *data = 0x6364;
    *(data+1) = 0x6162;
    for (i = 2; i < 8; i++)
        data[i] = i;
    rc5_init(&c, 16); /* 16 rounds */
    rc5_key(&c, key, 4);
    rc5_encrypt(&c, data, 4);
    printf("Encryptions:\n");
    for (i = 0; i < 8; i += 2)
        printf("Block %01d = %04x %04x\n",
               i / 2, data[i], data[i + 1]);

    rc5_decrypt(&c, data, 2);
    rc5_decrypt(&c, data + 4, 2);

    printf("Decryptions:\n");
    for (i = 0; i < 8; i += 2)
        printf("Block %01d = %04x %04x\n",
               i / 2, data[i], data[i + 1]);
}