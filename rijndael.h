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

/* Encryption operations */
void sub_bytes(unsigned char *block, aes_block_size_t block_size);
void shift_rows(unsigned char *block, aes_block_size_t block_size);
void mix_columns(unsigned char *block, aes_block_size_t block_size);

/* Decryption operations */
void invert_sub_bytes(unsigned char *block, aes_block_size_t block_size);
void invert_shift_rows(unsigned char *block, aes_block_size_t block_size);
void invert_mix_columns(unsigned char *block, aes_block_size_t block_size);

/* Shared operations */
void add_round_key(unsigned char *block, 
                   unsigned char *round_key,
                   aes_block_size_t block_size);

/* Key expansion */
unsigned char *expand_key(unsigned char *cipher_key, aes_block_size_t block_size);

/* Helper functions */
size_t block_size_to_bytes(aes_block_size_t block_size);

#endif
