//
// Created by jared on 2/27/18.
//

#include <time.h>
#include <stdlib.h>
#include <memory.h>
#include "crypt.h"

/**
 *
 * @param workspace
 * @param keylen
 * @return
 */
int prepare_data(s_data *workspace, const s_keypair *kp, uint32_t seed) {
    /* Calculate indexes for padding */
    int nzpad = ((int) kp->length + FDATA_HEADER_SIZE) % 4;

    if (nzpad > 0)
        nzpad = 4 - nzpad;

    int padding_start = (FDATA_HEADER_SIZE +
            (int) workspace->pt_len + nzpad) / sizeof(uint32_t);

    /* Begin formatting the data */
    ((uint16_t *) workspace->fpt)[0] = get_checksum(kp->tkey, kp->length);
    ((uint16_t *) workspace->fpt)[1] = workspace->pt_len;

    /* Copy the data */
    for (int i = 0; i < workspace->pt_len; i++)
        workspace->fpt[FDATA_HEADER_SIZE + i] = workspace->pt[i];

    /* Pad zeros for 32bit alignment */
    for (int r = 0; r < nzpad; r++)
        workspace->fpt[workspace->pt_len + FDATA_HEADER_SIZE + r] = 0;

    /* Pad the rest with random bits */
    for (int i = padding_start; i < kp->length / sizeof(uint32_t); i += sizeof(uint32_t))
        ((uint32_t *)workspace->fpt)[i] = (uint32_t) rand_r(&seed);

    return 0;
}

/**
 * Returns the `checksum` for a key (bytes 10 and length-1). This is used to test for
 * successful decryption and to validate that the message originated from an actor
 * that was in possession of the encryption key
 * @param key
 * @param keylen
 * @return an unsigned short representing the checksum
 */
inline uint16_t get_checksum(const uint8_t *key, uint16_t keylen) {
    return (uint16_t) (key[10] << 8 | key[keylen - 1] & 0xff);
}

/**
 *
 * @param workspace
 * @param kp
 */
inline void encrypt32(s_data *workspace, const s_keypair *kp) {
    for (int i = 0; i < kp->length >> 2; i++)
        ((uint32_t *)workspace->ct)[i] =
                ((uint32_t *)workspace->fpt)[i] ^ ((uint32_t *)kp->tkey)[i];
}

/**
 *
 * @param workspace
 * @param kp
 */
inline void decrypt32(s_data *workspace, const s_keypair *kp) {
    for (int i = 0; i < kp->length >> 2; i++)
        ((uint32_t *)workspace->fpt)[i] =
                ((uint32_t *)workspace->ct)[i] ^ ((uint32_t *)kp->tkey)[i];
}

/* Public functions */

/**
 *
 * @param workspace
 * @param keylen
 */
void clean_workspace(s_data *workspace, uint16_t keylen) {
    memset(workspace->pt, 0, workspace->pt_len);
    memset(workspace->fpt, 0, keylen);
    memset(workspace->ct, 0, keylen);
    workspace->pt_len = 0;
}

/**
 *
 * @param kp
 * @param workspace
 * @return
 */
srypto_result encrypt(s_keypair *kp, s_data *workspace) {
    /* Check advertised data length */
    if (workspace->pt_len > MAX_DATA_SIZE(kp->length))
        return S_ERROR_DATA_SIZE;

    /* Start by mutating the encryption key */
    keypair_permute_tkey(kp);

    /* Populates workspace->fpt (formatted plain text */
    if (prepare_data(workspace, kp, (uint32_t) time(NULL)) == -1)
        return S_ERROR_PREPARE;

    /* encrypt data and store cypher text (workspace->ct) */

    encrypt32(workspace, kp);

    /* Finally, permute the master key */

    keypair_permute_master(kp, workspace->fpt);

    return S_OK;
}

/**
 *
 * @param kp
 * @param workspace
 * @return
 */
srypto_result decrypt(s_keypair *kp, s_data *workspace) {

    uint8_t temp_key[kp->length];

    /* Save the key so we can revert permutation on
     * decryption failure */
    copy_key32(kp->tkey, temp_key, kp->length);

    /* permute encryption key */
    keypair_permute_tkey(kp);

    /* Attempt decrypt */
    decrypt32(workspace, kp);

    /* Verify checksum */
    if (get_checksum(kp->tkey, kp->length) != ((uint16_t *)workspace->fpt)[0]) {
        /* Restore key */
        copy_key32(temp_key, kp->tkey, kp->length);
        return S_ERROR_VERIFY;
    }

    /* Copy the plain text into the workspace */
    workspace->pt_len = ((uint16_t *)workspace->fpt)[1];
    for (int i = 0; i < workspace->pt_len; i++)
        workspace->pt[i] = workspace->fpt[i+FDATA_HEADER_SIZE];

    /* Mutate the master key */
    keypair_permute_master(kp, workspace->fpt);

    return S_OK;

}
