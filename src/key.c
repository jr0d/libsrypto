#include "key.h"

/**
 * Initialize the key using the linear method
 * @param key
 * @param length
 */
void key_init_linear(uint8_t *key, uint16_t length) {
    uint32_t *window = (uint32_t *) key;

    for(uint16_t i = 0; i < (length >> 2); i++){
        window[i] = 0x0;
        for (uint8_t j = 0; j < 4; j++) {
            window[i] = (uint32_t) (window[i] | ((i * 4 + j) << (8 * (3 - j))));
        }
    }
}
/**
 * Copy key in 32bit chunks
 * @param src
 * @param dest
 * @param length
 */
void copy_key32(const uint8_t *src, uint8_t *dest, uint16_t length) {
    for (int i = 0; i < length >> 2; i++)
        ((uint32_t *)dest)[i] = ((uint32_t *)src)[i];
}
