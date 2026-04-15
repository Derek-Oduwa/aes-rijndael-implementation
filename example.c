#include <stdio.h>
#include "rijndael.h"

int main() {
    printf("AES Encryption Example\n");
    printf("======================\n\n");
    
    unsigned char plaintext[16] = "Hello AES World!";
    unsigned char key[16] = "MySecretKey12345";
    
    printf("Plaintext: %s\n", plaintext);
    
    unsigned char *ciphertext = aes_encrypt_block(plaintext, key, AES_BLOCK_128);
    printf("Encrypted (hex): ");
    for(int i = 0; i < 16; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
    
    unsigned char *decrypted = aes_decrypt_block(ciphertext, key, AES_BLOCK_128);
    printf("Decrypted: %s\n", decrypted);
    
    free(ciphertext);
    free(decrypted);
    return 0;
}