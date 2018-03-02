//
// Created by jared on 2/28/18.
//

#include <stdio.h>
#include <memory.h>
#include "srypto.h"

#define KEY_LENGTH 256  /* BYTES */


int main(int argc, char **argv) {
    // Keys
    // TODO: master key should be stored on the file system or generated
    uint8_t master[] = "\x50\x6b\x28\x26\x11\x59\xb9\xbe\x50\xba\x25\x4e\x03\x53\xd9\x88\xf9\xe9\x11\xe3"
            "\xcf\x0a\xaa\xe8\xd5\x1e\xa7\x37\x18\x0b\xe1\x75\x4b\xc8\x7d\xdf\x6d\xca\x3a\xd6\x2c\xe7\x31\xb8\x33\x57"
            "\xc7\x29\x00\x59\xcc\xf3\xbd\x3f\x2b\x7c\xfd\xc2\xd8\x7b\x9e\xd2\xd9\x88\xf7\x82\x4f\x15\xdd\xd9\xb4\x95"
            "\x8f\xed\x4b\x3a\x97\xbc\xf7\xa3\x60\xe8\x4d\x22\xb1\x65\xb7\x1d\x33\xb9\xff\xe1\x09\xf5\xfd\xe8\x9b\x3c"
            "\x0f\x2f\x73\x00\xbb\xa0\x78\x9f\xbf\xda\x63\x08\x0f\x92\xd6\xfe\xab\x9e\xb7\xb9\xbb\x34\xf6\xf9\xa2\xdd"
            "\xf8\xac\xb8\xeb\x82\xcb\xe3\xba\xac\x7f\xd6\x59\xe9\x75\x06\xe1\x3e\xb6\xb3\x47\xa6\xfa\x25\x9f\x83\x81"
            "\xd0\xf8\xc6\x17\x42\x91\xd0\x59\xfa\xb1\x66\x94\x10\x08\x18\x06\x14\x8c\x81\x36\xe3\x91\x3b\x0b\x4e\x7b"
            "\xb4\xce\x7a\xee\x86\x14\x19\xed\x92\xcd\x70\x7d\x30\xb6\x54\x38\x9a\x57\x35\x5e\x64\xab\xae\x59\x69\x02"
            "\x03\xd6\x4e\x6e\x2a\xeb\xd6\xba\xa3\x15\xf4\x69\x6a\x74\xe4\x2e\xf5\xe5\x66\x4b\x85\xbf\xef\x27\x24\x56"
            "\x85\x4c\x2d\xa0\x65\xf4\x20\x9c\xde\x18\x3a\x28\xcd\x48\x3c\x3d\x49\xf9\x5e\x4f\xd6\x82\xce\x6d\x82\x92"
            "\x4b\xb3";

    uint8_t master_temp[KEY_LENGTH];
    uint8_t tkey[KEY_LENGTH];

    // Copied from the workspace and used for decryption test
    uint8_t temp_ct[KEY_LENGTH];

    key_init_linear((uint8_t *) tkey, KEY_LENGTH);

    // Keypair structure
    s_keypair kp;

    kp.length = KEY_LENGTH;
    kp.master = (uint8_t *) master;
    kp.tkey = (uint8_t *) tkey;

    // Load workspace with plain text
    s_data workspace;
    memset(&workspace, 0, sizeof(workspace));

    uint8_t plain_text[] = "The cake is a lie!";
    uint8_t fplain_text[256] = "";
    uint8_t cypher_text[256] = "";

    workspace.pt = (uint8_t *) plain_text;
    workspace.pt_len = (uint16_t) sizeof(plain_text) + 1;
    workspace.fpt = (uint8_t *) fplain_text;
    workspace.ct = (uint8_t *) cypher_text;

    printf("**** libsrypto test ****\n\n");

    printf("Plain text: %s\n\n", plain_text);

    // Encrypt ( this causes master to mutate, so copy it (for testing, normally we wouldn't be encrypting and
    // decrypting in the same context))
    copy_key32((uint8_t *)master, (uint8_t *)master_temp, KEY_LENGTH);

    encrypt(&kp, &workspace);

    printf("Cypher Text:\n\n");
    for (int i = 0; i < KEY_LENGTH >> 2; i++) {
        printf("0x%x ", ((uint32_t *) workspace.ct)[i]);
        if ((i+1) % 8  == 0) printf("\n");
    }
    printf("\n\n");

    // Since fpt and ct are the same size as KEY_LENGTH, use  this function to copy
    // Like a boss
    copy_key32(workspace.ct, temp_ct, KEY_LENGTH); // copy the cypher text into the temp_ct array

    // Nuke all the plain text data to prove decryption works
    clean_workspace(&workspace, KEY_LENGTH);

    // Restore Master
    copy_key32(master_temp, master, KEY_LENGTH);

    // Reset the encryption key
    key_init_linear(tkey, KEY_LENGTH);

    // prepare workspace for decrypt
    workspace.ct = (uint8_t *) temp_ct;

    srypto_result result;

    if ((result = decrypt(&kp, &workspace)) != S_OK) {
        printf("There was a problem: %d", result);
    }

    printf("Decrypted plain text: %s\n", workspace.pt);
}
