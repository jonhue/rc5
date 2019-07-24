#include <time.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <sysexits.h>
#include "perf.h"
#include "rc5.h"
#include "test.h"
#include "references/rfc2040.h"

static void test(void *buffer);
static inline double curtime(void);
static void print_results(void);
static int modeNo;
static double start;
static u_char key[] = "0123456789";

#define test_func(mode_name, function) \
start = curtime(); \
function; \
modes[modeNo].result += curtime() - start; \
*modes[modeNo].name = #mode_name; \
break; \

#define SIZE MAX_CIPHER_LENGTH
#define ITERATIONS 20
#define MODE_COUNT 6

struct mode {
    char *name[12];
    double result;
} modes[MODE_COUNT];

static test_vector *ptv;

void run_perf_tests() {
    // Round keys sichern
    size_t s_len = (2 * ROUNDS + 2) * 2;
    void *s = malloc(s_len);
    if (s == NULL) {
        err(EX_IOERR, "Could not allocate memory for testing");
    }
    memcpy(s, roundkeys, s_len);

    void *buffer = malloc(SIZE);
    if (buffer == NULL) {
        err(EX_IOERR, "Could not allocate memory for testing");
    }
    void *bufferBackup = malloc(SIZE);
    if (bufferBackup == NULL) {
        free(buffer);
        err(EX_IOERR, "Could not allocate memory for testing");
    }
    memcpy(bufferBackup, buffer, SIZE);

    ptv = setup_RFC2040_testvector(0, (char *) key, sizeof(key) - 1, buffer, SIZE, 0x11223344);

    printf("Testing with %u bytes and %d iterations\n\n", SIZE, ITERATIONS);
    for (modeNo = 0; modeNo < MODE_COUNT; modeNo++) {
        modes[modeNo].result = 0;
        for (int iterations = 0; iterations < ITERATIONS; iterations++) {
            test(buffer);
            memcpy(buffer, bufferBackup, SIZE);
            memcpy(roundkeys, s, s_len);
        }
        modes[modeNo].result /= ITERATIONS;
    }
    free(buffer);
    free(bufferBackup);
    free(s);
    print_results();
}

static void test(void *buffer) {
    size_t keylen = sizeof(key);
    switch (modeNo) {
        case 0: test_func(cbc_enc, rc5_cbc_enc(key, keylen, buffer, SIZE, 1234))
        case 1: test_func(cbc_enc_ref, run_rfc2040_test(ptv, 0))
        case 2: test_func(cbc_dec, rc5_cbc_dec(key, keylen, buffer, SIZE, 1234))
        case 3: test_func(ecb_enc, rc5_ecb_enc(key, keylen, buffer, SIZE))
        case 4: test_func(ecb_dec, rc5_ecb_dec(key, keylen, buffer, SIZE))
        case 5: test_func(ctr, rc5_ctr(key, keylen, buffer, SIZE))
        default: printf("Function number %u not found\n", modeNo); break;
    }
}

static void print_results(void) {
    for (modeNo = 0; modeNo < MODE_COUNT; modeNo++) {
        printf("%-11s %6.3f\n", *modes[modeNo].name, modes[modeNo].result);
    }
}

static inline double curtime(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}
