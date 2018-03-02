//
// Created by jared on 3/2/18.
//

#include "rng.h"

static uint32_t mt[N];
static uint16_t index;

void rng_init(const uint32_t seed) {
    uint32_t i;

    mt[0] = seed;

    for (i = 1; i < N; i++) {
        mt[i] = (F * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i);
    }

    index = N;
}

static void twist() {
    uint32_t i, x, xA;

    for (i = 0; i < N; i++) {
        x = (mt[i] & MASK_UPPER) + (mt[(i + 1) % N] & MASK_LOWER);

        xA = x >> 1;

        if (x & 0x1)
            xA ^= A;

        mt[i] = mt[(i + M) % N] ^ xA;
    }

    index = 0;
}

uint32_t get_random32() {
    uint32_t y;
    int i = index;

    if (index >= N) {
        twist();
        i = index;
    }

    y = mt[i];
    index = i + 1;

    y ^= (mt[i] >> U);
    y ^= (y << S) & B;
    y ^= (y << T) & C;
    y ^= (y >> L);

    return y;
}
