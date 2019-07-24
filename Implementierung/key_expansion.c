#include "rc5.h"

extern void key_expansion(uint16_t *roundkeys);

int main() {
    int size = 2*ROUNDS + 2;
    uint16_t *roundkeys = malloc(2*size);
    if (roundkeys == NULL) {
        return -1;
    }

    key_expansion(roundkeys);
    for (int i = 0; i < size; i++) {
        printf("0x%04x  ", *(roundkeys + i));
        if (i % 8 == 7) {
            printf("\n");
        }
    }
    printf("\n");

    free(roundkeys);
    return 0;
}
