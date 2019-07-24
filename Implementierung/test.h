#ifndef TEST_H
#define TEST_H

#include <stdlib.h>
#include <string.h>
#include "rc5.h"
#include "references/rfc2040.h"

void run_test(char *id);

test_vector *setup_RFC2040_testvector(int padding, char *key, size_t key_length, char *plain,
                                      int plain_length, uint32_t iv);

extern uint16_t roundkeys[34./];

#endif
