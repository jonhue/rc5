#ifndef RC5_BUFFERIO_H
#define RC5_BUFFERIO_H

#include <stdio.h>

long read_file(const char *restrict path, void *restrict buffer, size_t size);

int write_file(const char *restrict path, const void *restrict buffer, size_t size);

#endif
