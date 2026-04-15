/*
 * Derek Oduwa
 * C21371446
 * 
 * AES(Rijndael) implementation
 * This library implements the AES encryption and decryption algorithms
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rijndael.h"

/* AES S-box (substitution box) for SubBytes operation */
static const unsigned char sbox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/* Inverse S-box for InvSubBytes operation */
static const unsigned char inv_sbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/* Round constant for key expansion */
static const unsigned char rcon[11] = {
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* Convert block size to number of bytes */
size_t block_size_to_bytes(aes_block_size_t block_size) {
  switch (block_size) {
  case AES_BLOCK_128:
    return 16;
  case AES_BLOCK_256:
    return 32;
  case AES_BLOCK_512:
    return 64;
  default:
    fprintf(stderr, "Invalid block size %d\n", block_size);
    exit(1);
  }
}
/*
* Access a block as a 2D array (state matrix)
* Blocks are stored in row-major order but accessed as column-major
 */

unsigned char block_access(unsigned char *block, size_t row, size_t col, aes_block_size_t block_size) {
  int row_len;
  switch (block_size) {
    case AES_BLOCK_128:
      row_len = 4;
      break;
    case AES_BLOCK_256:
      row_len = 8;
      break;
    case AES_BLOCK_512:
      row_len = 16;
      break;
    default:
      fprintf(stderr, "Invalid block size for block_access: %d\n", block_size);
      exit(1);
  }

  return block[(row * row_len) + col];
}

char *message(char n) {
  char *output = (char *)malloc(7);
  strcpy(output, "hello");
  output[5] = n;
  output[6] = 0;
  return output;
}

/**
 * SubBytes Transformation
 * 
 * This function performs a non-linear byte substitution on each byte of the state
 * using the Rijndael S-box. The S-box is a lookup table that provides confusion
 * in the cipher, making it resistant to linear and differential cryptanalysis.
 * 
 * @param block Pointer to the state block to transform
 * @param block_size The size of the block (128, 256, or 512 bits)
 */
void sub_bytes(unsigned char *block, aes_block_size_t block_size) {
    size_t bytes = block_size_to_bytes(block_size);
  for (size_t i = 0; i < bytes; i++) {
    block[i] = sbox[block[i]];
  }
}

/**
 * ShiftRows - cyclically shift the rows of the state
 * Row 0: no shift
 * Row 1: shift left by 1
 * Row 2: shift left by 2
 * Row 3: shift left by 3
 */
void shift_rows(unsigned char *block, aes_block_size_t block_size) {
  int cols;
  switch (block_size) {
    case AES_BLOCK_128:
      cols = 4;
      break;
    case AES_BLOCK_256:
      cols = 8;
      break;
    case AES_BLOCK_512:
      cols = 16;
      break;
    default:
      fprintf(stderr, "Invalid block size in shift_rows\n");
      exit(1);
  }
  
  // Temporary buffer for one row
  unsigned char temp[16]; // Max row size for 512-bit blocks
  
  // Shift each row
  for (int row = 1; row < 4; row++) {  // Row 0 doesn't shift
    // Copy the row to temp
    for (int col = 0; col < cols; col++) {
      temp[col] = block[row * cols + col];
    }
    
    // Shift the row left by 'row' positions
    for (int col = 0; col < cols; col++) {
      block[row * cols + col] = temp[(col + row) % cols];
    }
  }
}

/**
 * Galois Field multiplication by 2
 */
static unsigned char gmul2(unsigned char a) {
  return (a << 1) ^ (((a >> 7) & 1) * 0x1b);
}

/**
 * Galois Field multiplication by 3
 */
static unsigned char gmul3(unsigned char a) {
  return gmul2(a) ^ a;
}

/**
 * Galois Field multiplication (general case)
 */
static unsigned char gmul(unsigned char a, unsigned char b) {
  unsigned char p = 0;
  for (int i = 0; i < 8; i++) {
    if (b & 1) {
      p ^= a;
    }
    unsigned char hi_bit_set = (a & 0x80);
    a <<= 1;
    if (hi_bit_set) {
      a ^= 0x1b;
    }
    b >>= 1;
  }
  return p;
}

void mix_columns(unsigned char *block, aes_block_size_t block_size) {
  int cols;
  switch (block_size) {
    case AES_BLOCK_128:
      cols = 4;
      break;
    case AES_BLOCK_256:
      cols = 8;
      break;
    case AES_BLOCK_512:
      cols = 16;
      break;
    default:
      fprintf(stderr, "Invalid block size in mix_columns\n");
      exit(1);
  }
  
  unsigned char temp[4];
  
  for (int col = 0; col < cols; col++) {
    temp[0] = block[0 * cols + col];
    temp[1] = block[1 * cols + col];
    temp[2] = block[2 * cols + col];
    temp[3] = block[3 * cols + col];
    
    block[0 * cols + col] = gmul2(temp[0]) ^ gmul3(temp[1]) ^ temp[2] ^ temp[3];
    block[1 * cols + col] = temp[0] ^ gmul2(temp[1]) ^ gmul3(temp[2]) ^ temp[3];
    block[2 * cols + col] = temp[0] ^ temp[1] ^ gmul2(temp[2]) ^ gmul3(temp[3]);
    block[3 * cols + col] = gmul3(temp[0]) ^ temp[1] ^ temp[2] ^ gmul2(temp[3]);
  }
}

/*
 * Operations used when decrypting a block
 */
void invert_sub_bytes(unsigned char *block, aes_block_size_t block_size) {
  size_t bytes = block_size_to_bytes(block_size);
  for (size_t i = 0; i < bytes; i++) {
    block[i] = inv_sbox[block[i]];
  }
}

void invert_shift_rows(unsigned char *block, aes_block_size_t block_size) {
  int cols;
  switch (block_size) {
    case AES_BLOCK_128:
      cols = 4;
      break;
    case AES_BLOCK_256:
      cols = 8;
      break;
    case AES_BLOCK_512:
      cols = 16;
      break;
    default:
      fprintf(stderr, "Invalid block size in invert_shift_rows\n");
      exit(1);
  }
  
  unsigned char temp[16];
  
  // Shift each row RIGHT instead of left
  for (int row = 1; row < 4; row++) {
    for (int col = 0; col < cols; col++) {
      temp[col] = block[row * cols + col];
    }
    
    // Shift right by 'row' positions (same as shift left by cols - row)
    for (int col = 0; col < cols; col++) {
      block[row * cols + col] = temp[(col + cols - row) % cols];
    }
  }
}

void invert_mix_columns(unsigned char *block, aes_block_size_t block_size) {
  int cols;
  switch (block_size) {
    case AES_BLOCK_128:
      cols = 4;
      break;
    case AES_BLOCK_256:
      cols = 8;
      break;
    case AES_BLOCK_512:
      cols = 16;
      break;
    default:
      fprintf(stderr, "Invalid block size in invert_mix_columns\n");
      exit(1);
  }
  
  unsigned char temp[4];
  
  for (int col = 0; col < cols; col++) {
    temp[0] = block[0 * cols + col];
    temp[1] = block[1 * cols + col];
    temp[2] = block[2 * cols + col];
    temp[3] = block[3 * cols + col];
    
    block[0 * cols + col] = gmul(temp[0], 0x0e) ^ gmul(temp[1], 0x0b) ^ 
                            gmul(temp[2], 0x0d) ^ gmul(temp[3], 0x09);
    block[1 * cols + col] = gmul(temp[0], 0x09) ^ gmul(temp[1], 0x0e) ^ 
                            gmul(temp[2], 0x0b) ^ gmul(temp[3], 0x0d);
    block[2 * cols + col] = gmul(temp[0], 0x0d) ^ gmul(temp[1], 0x09) ^ 
                            gmul(temp[2], 0x0e) ^ gmul(temp[3], 0x0b);
    block[3 * cols + col] = gmul(temp[0], 0x0b) ^ gmul(temp[1], 0x0d) ^ 
                            gmul(temp[2], 0x09) ^ gmul(temp[3], 0x0e);
  }
}

/*
 * This operation is shared between encryption and decryption
 */

void add_round_key(unsigned char *block, 
                   unsigned char *round_key,
                   aes_block_size_t block_size) {
  size_t bytes = block_size_to_bytes(block_size);
  for (size_t i = 0; i < bytes; i++) {
    block[i] ^= round_key[i];
  }
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
/**
 * RotWord - rotate a 4-byte word left by one byte
 * [a0, a1, a2, a3] becomes [a1, a2, a3, a0]
 */
static void rot_word(unsigned char *word) {
  unsigned char temp = word[0];
  word[0] = word[1];
  word[1] = word[2];
  word[2] = word[3];
  word[3] = temp;
}

/**
 * SubWord - apply S-box to each byte in a 4-byte word
 */
static void sub_word(unsigned char *word) {
  word[0] = sbox[word[0]];
  word[1] = sbox[word[1]];
  word[2] = sbox[word[2]];
  word[3] = sbox[word[3]];
}

/**
 * Key expansion - expand the cipher key into round keys
 * For 128-bit: 16 bytes -> 176 bytes (11 round keys)
 * For 256-bit: 32 bytes -> 352 bytes (11 round keys)
 * For 512-bit: 64 bytes -> 704 bytes (11 round keys)
 */
unsigned char *expand_key(unsigned char *cipher_key, aes_block_size_t block_size) {
  size_t key_bytes = block_size_to_bytes(block_size);
  size_t expanded_size = key_bytes * 11; // 11 round keys for all block sizes
  
  unsigned char *expanded = (unsigned char *)malloc(expanded_size);
  if (!expanded) {
    fprintf(stderr, "Memory allocation failed in expand_key\n");
    exit(1);
  }
  
  // Copy the original key as the first round key
  memcpy(expanded, cipher_key, key_bytes);
  
  // Number of 32-bit words in the key
  int nk = key_bytes / 4;  // 4 for 128-bit, 8 for 256-bit, 16 for 512-bit
  
  // Total number of 32-bit words needed (11 round keys)
  int total_words = (key_bytes / 4) * 11;
  
  unsigned char temp[4];
  
  // Generate the rest of the round keys
  for (int i = nk; i < total_words; i++) {
    // Copy the previous word
    memcpy(temp, &expanded[(i - 1) * 4], 4);
    
    // Every Nk words, apply special transformation
    if (i % nk == 0) {
      rot_word(temp);
      sub_word(temp);
      temp[0] ^= rcon[i / nk];
    }
    // For 256-bit and 512-bit keys, apply SubWord at certain positions
    else if (nk > 6 && i % nk == 4) {
      sub_word(temp);
    }
    
    // XOR with word Nk positions back
    for (int j = 0; j < 4; j++) {
      expanded[i * 4 + j] = expanded[(i - nk) * 4 + j] ^ temp[j];
    }
  }
  
  return expanded;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
/**
 * AES Encryption - main encryption function
 */

 unsigned char *aes_encrypt_block(unsigned char *plaintext,
                                 unsigned char *key,
                                 aes_block_size_t block_size) {
  size_t bytes = block_size_to_bytes(block_size);
  
  // Allocate memory for the ciphertext
  unsigned char *output = (unsigned char *)malloc(bytes);
  if (!output) {
    fprintf(stderr, "Memory allocation failed in aes_encrypt_block\n");
    exit(1);
  }
  
  // Copy plaintext to output (we'll work on it in place)
  memcpy(output, plaintext, bytes);
  
  // Expand the key
  unsigned char *round_keys = expand_key(key, block_size);
  
  // Round 0: AddRoundKey only
  add_round_key(output, &round_keys[0], block_size);
  
  // Rounds 1-9: SubBytes, ShiftRows, MixColumns, AddRoundKey
  for (int round = 1; round < 10; round++) {
    sub_bytes(output, block_size);
    shift_rows(output, block_size);
    mix_columns(output, block_size);
    add_round_key(output, &round_keys[round * bytes], block_size);
  }
  
  // Round 10: SubBytes, ShiftRows, AddRoundKey (no MixColumns)
  sub_bytes(output, block_size);
  shift_rows(output, block_size);
  add_round_key(output, &round_keys[10 * bytes], block_size);
  
  free(round_keys);
  return output;
}
unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key,
                                 aes_block_size_t block_size) {
  size_t bytes = block_size_to_bytes(block_size);
  
  unsigned char *output = (unsigned char *)malloc(bytes);
  if (!output) {
    fprintf(stderr, "Memory allocation failed in aes_decrypt_block\n");
    exit(1);
  }
  
  memcpy(output, ciphertext, bytes);
  
  unsigned char *round_keys = expand_key(key, block_size);
  
  // Round 10: AddRoundKey, InvShiftRows, InvSubBytes
  add_round_key(output, &round_keys[10 * bytes], block_size);
  invert_shift_rows(output, block_size);
  invert_sub_bytes(output, block_size);
  
  // Rounds 9-1
  for (int round = 9; round >= 1; round--) {
    add_round_key(output, &round_keys[round * bytes], block_size);
    invert_mix_columns(output, block_size);
    invert_shift_rows(output, block_size);
    invert_sub_bytes(output, block_size);
  }
  
  // Round 0
  add_round_key(output, &round_keys[0], block_size);
  
  free(round_keys);
  return output;
}