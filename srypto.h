//
// Created by jared on 2/26/18.
//

#ifndef LIBSRYPTO_SRYPTO_H
#define LIBSRYPTO_SRYPTO_H

#include <stddef.h>
#include <stdint.h>

/**
 *
 */
typedef struct {
    uint16_t length;
    uint8_t * master;
    uint8_t * tkey;
} s_keypair;

/**
 *
 * @param key
 * @param length
 */
extern void key_init_linear(uint8_t *key, uint16_t length);

/**
 *
 * @param kp
 */
extern void keypair_permute_tkey(s_keypair *kp);

/**
 *
 * @param kp
 * @param data
 */
extern void keypair_permute_master(s_keypair *kp, const uint8_t *data);
#endif //LIBSRYPTO_SRYPTO_H
