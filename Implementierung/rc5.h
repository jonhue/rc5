#include <bsd/stdlib.h>

#ifndef RC5_RC5_H
#define RC5_RC5_H

void cleanup(void);

long read_file(const char *restrict path, void *restrict buffer, size_t size);

int write_file(const char *restrict path, const void *restrict buffer, size_t size);

void fclose_keep_errno(FILE *file);

void pkcs7_pad(void *buf, size_t len);

void rc5_cbc_enc(unsigned char *key, size_t keylen, uint32_t *buffer, size_t len, uint32_t iv);

void rc5_cbc_dec(unsigned char *key, size_t keylen, uint32_t *buffer, size_t len, uint32_t iv);

void usage(const char *restrict program_name);

extern void rc5_init(unsigned char *key, size_t keylen, void *l);

extern void rc5_enc(uint32_t *buffer);

extern void rc5_dec(uint32_t *buffer);

#endif
