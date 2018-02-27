//
// Created by jared on 2/27/18.
//

#include <time.h>
#include <stdlib.h>
#include "crypt.h"

/**
 *
 * @param workspace
 * @param keylen
 * @return
 */
int prepare_data(s_data *workspace, uint16_t keylen) {
    time_t seed;
    if ((seed = time(NULL)) == -1) {
        return -1;  /// Getting time error
    }

    /* Calculate indexes for padding */
    int nzpad = ((int) keylen + FDATA_HEADER_SIZE) % 4;
    if (nzpad > 0)
        nzpad = 4 - nzpad;

    int padding_start = (FDATA_HEADER_SIZE +
            (int) workspace->pt_len + nzpad) / sizeof(uint32_t);

    /* Begin formatting the data */
    ((uint16_t *) workspace->fpt)[0] = workspace->checksum;
    ((uint16_t *) workspace->fpt)[1] = workspace->pt_len;

    /* Copy the data */
    for (int i = 0; i < workspace->pt_len; i++)
        workspace->fpt[FDATA_HEADER_SIZE + i] = workspace->pt[i];

    // Pad zeros for 32bit alignment
    for (int r = 0; r < nzpad; r++)
        workspace->fpt[workspace->pt_len + FDATA_HEADER_SIZE + r] = 0;

    // Pad with random bits
    for (int i = padding_start; i < keylen / sizeof(uint32_t); i += sizeof(uint32_t))
        ((uint32_t *) workspace->fpt)[i] = (uint32_t) rand_r((unsigned int *) &seed);

    return 0;
}