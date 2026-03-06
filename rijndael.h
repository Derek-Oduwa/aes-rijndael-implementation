/*
 * Derek Oduwa
 * C21371446
 * 
 * AES(Rijndael) implementation
 * This library implements the AES encryption and decryption algorithms
 * for block sizes of 128, 256, and 512 bits. 
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

typedef enum {
  AES_BLOCK_128,
  AES_BLOCK_256,
  AES_BLOCK_512
} aes_block_size_t;

/* Helper functions to access block as a 2D array */
unsigned char block_access(unsigned char *block,
                           size_t row, size_t col,
                           aes_block_size_t block_size);

/*
 * Main encrypt/decrypt functions
 */
unsigned char *aes_encrypt_block(
    unsigned char *plaintext,
    unsigned char *key,
    aes_block_size_t block_size);

    
unsigned char *aes_decrypt_block(
    unsigned char *ciphertext,
    unsigned char *key,
    aes_block_size_t block_size);

#endif
