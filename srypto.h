//
// Created by jared on 2/26/18.
//

#ifndef LIBSRYPTO_SRYPTO_H
#define LIBSRYPTO_SRYPTO_H

#include <stddef.h>
#include <stdint.h>

/**
 * The size of the data packet header, used to calculate MAX_DATA_SIZE
 * for chunking.
 */
#define FDATA_HEADER_SIZE 4
#define MAX_DATA_SIZE(keylen) ((keylen) - FDATA_HEADER_SIZE)


/**
 * The keypair structure, used to keep track of master and tkey(encryption key)
 * relationship
 */
typedef struct {
    uint16_t length;  /// The key size we are using
    uint8_t * master;
    uint8_t * tkey; /// The encryption key
} s_keypair;

/**
 * Three buffers needed for encryption/decryption, also a place to store the checksum data
 */
typedef struct{
    uint8_t * pt; /// plain text
    uint8_t * fpt; /// formatted plain text
    uint8_t * ct; /// cypher text
    uint16_t pt_len; /// plain text length
} s_data;

/**
 * Returned from public encrypt/decrypt functions
 */
typedef enum {
    S_OK,
    S_ERROR_DATA_SIZE,
    S_ERROR_PREPARE,
    S_ERROR_VERIFY
} srypto_result;

/**
 *
 * @param key
 * @param length
 */
extern void key_init_linear(uint8_t *key, uint16_t length);

/**
 *
 * @param src
 * @param dest
 * @param length
 */
extern void copy_key32(const uint8_t *src, uint8_t *dest, uint16_t length);

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

/**
 *
 * @param workspace
 */
extern void clean_workspace(s_data *workspace, uint16_t keylen);

/**
 *
 * @param kp
 * @param workspace
 * @return
 */
extern srypto_result encrypt(s_keypair *kp, s_data *workspace);

/**
 *
 * @param kp
 * @param workspace
 * @return
 */
extern srypto_result decrypt(s_keypair *kp, s_data *workspace);

#endif //LIBSRYPTO_SRYPTO_H
