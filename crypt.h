//
// Created by jared on 2/27/18.
//

#ifndef LIBSRYPTO_CRYPT_H
#define LIBSRYPTO_CRYPT_H

#include "srypto.h"

int prepare_data(s_data *workspace, const s_keypair *kp, uint32_t seed);

__always_inline inline uint16_t get_checksum(const uint8_t *key, uint16_t keylen);
__always_inline inline void encrypt32(s_data *workspace, const s_keypair *kp);
__always_inline inline void decrypt32(s_data *workspace, const s_keypair *kp);

#endif //LIBSRYPTO_CRYPT_H
