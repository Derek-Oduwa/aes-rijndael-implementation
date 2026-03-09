# AES (Rijndael) Implementation in C

**Author:** Derek Oduwa (C21371446)
**Course:** Secure Systems Development  
**Assignment:** Assignment 2 - AES Implementation

## Overview

This project implements the AES (Advanced Encryption Standard) encryption algorithm in C, supporting 128-bit, 256-bit, and 512-bit block sizes.

## Project Structure

```
.
├── rijndael.h          # Header file with function declarations
├── rijndael.c          # Implementation of AES algorithm
├── main.c              # Demo program
├── test_aes.py         # Python unit tests
├── Makefile            # Build configuration
├── python-aes/         # Reference Python implementation (submodule)
└── .github/workflows/  # CI/CD pipeline
```

## Building

```bash
make clean
make
```

This will create:
- `main` - Demo executable
- `rijndael.so` - Shared library for Python tests

## Running Tests

```bash
python3 test_aes.py
```

## Implementation Status

### Completed
- [x] S-box and Inverse S-box lookup tables
- [x] `sub_bytes()` - Byte substitution
- [x] `invert_sub_bytes()` - Inverse byte substitution
- [x] `add_round_key()` - Round key addition

### In Progress
- [ ] `shift_rows()` - Row shifting
- [ ] `invert_shift_rows()` - Inverse row shifting
- [ ] `mix_columns()` - Column mixing
- [ ] `invert_mix_columns()` - Inverse column mixing
- [ ] `expand_key()` - Key expansion
- [ ] `aes_encrypt_block()` - Full encryption
- [ ] `aes_decrypt_block()` - Full decryption

## Development Workflow

1. Implement a function in `rijndael.c`
2. Add unit tests in `test_aes.py`
3. Run `make && python3 test_aes.py`
4. Commit changes
5. GitHub Actions will automatically build and test

## Resources

- [FIPS 197 - AES Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
- [Reference Python Implementation](https://github.com/boppreh/aes)
- Course materials and tutorials
