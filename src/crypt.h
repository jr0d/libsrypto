//
// Created by jared on 2/27/18.
//

#ifndef LIBSRYPTO_CRYPT_H
#define LIBSRYPTO_CRYPT_H

#include "srypto.h"

int prepare_data(s_data *workspace, const s_keypair *kp, uint32_t seed);

static inline void encrypt32(s_data *workspace, const s_keypair *kp);
static inline void decrypt32(s_data *workspace, const s_keypair *kp);

#endif //LIBSRYPTO_CRYPT_H
