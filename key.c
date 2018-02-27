#include "key.h"

void key_init_linear(uint8_t *key, uint16_t length) {
    uint32_t *window = (uint32_t *) key;

    for(uint16_t i = 0; i < (length >> 2); i++){
        window[i] = 0x0;
        for (uint8_t j = 0; j < 4; j++) {
            window[i] = (uint32_t) (window[i] | ((i * 4 + j) << (8 * (3 - j))));
        }
    }
}
