//
// Created by jared on 2/26/18.
//

#include "keypair.h"

/**
 * @param kp an initialized s_keypair structure
 * @typedef s_keypair
 */
void keypair_permute_tkey(s_keypair *kp) {
    for (uint16_t i = 0; i < kp->length; i++) {
        uint8_t temp = kp->tkey[i];
        uint16_t swap_idx = (uint16_t) kp->master[i];

        kp->tkey[i] = kp->tkey[swap_idx];
        kp->tkey[swap_idx] = temp;
    }
}

/**
 * @name keypair_permute_master
 * @details
 *
 * @param kp the s_keypair structure
 * @param data key length data packet used to permute the master
 * so that it can be used to encrypt more data
 */
void keypair_permute_master(s_keypair *kp, const uint8_t *data) {
    for (uint16_t i = 0; i < kp->length; i+=4 ) {
        ((uint32_t *)kp->master)[i] = ((uint32_t *)kp->master)[i] +
                                      ((uint32_t *)kp->tkey)[i]   +
                                      ((uint32_t *)data)[i];
    }
}