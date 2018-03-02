//
// Created by jared on 3/2/18.
//

#ifndef LIBSRYPTO_RNG_H
#define LIBSRYPTO_RNG_H

#include <stdint.h>

enum {
    N = 624,
    M = 397,
    R = 31,
    A = 0x9908B0DF,
    F = 1812433253,
    U = 11,
    S = 7,
    B = 0x9D2C5680,
    T = 15,
    C = 0xEFC60000,
    L = 18,

    MASK_LOWER = (1ull << R) - 1,
    MASK_UPPER = (1ull << R)
};

void rng_init(uint32_t seed);

uint32_t get_random32(void);


#endif //LIBSRYPTO_RNG_H
