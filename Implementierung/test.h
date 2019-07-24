#ifndef TEST_H
#define TEST_H

#include <stdlib.h>
#include <string.h>
#include "rc5.h"
#include "references/rfc2040.h"

extern uint16_t roundkeys[34];

void run_test(char *id);

#endif