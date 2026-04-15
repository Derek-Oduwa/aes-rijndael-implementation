#!/usr/bin/env python3
"""
Unit tests for AES implementation
Tests individual functions against the reference Python implementation
"""

import ctypes
import sys
import os

# Add the Python AES reference implementation to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'python-aes'))

try:
    import aes
except ImportError:
    print("Error: Could not import reference AES implementation")
    print("Make sure you've added it as a submodule: git submodule add https://github.com/boppreh/aes.git python-aes")
    sys.exit(1)

# Load the compiled C library
try:
    rijndael = ctypes.CDLL('./rijndael.so')
except OSError:
    print("Error: Could not load rijndael.so")
    print("Make sure you've compiled it with: make")
    sys.exit(1)

def test_sub_bytes():
    """Test the sub_bytes function"""
    print("Testing sub_bytes...")
    
    import random
    random.seed(42)
    
    passed = 0
    failed = 0
    
    for test_num in range(3):
        test_block = bytes([random.randint(0, 255) for _ in range(16)])
        
        c_block = ctypes.create_string_buffer(test_block, 16)
        rijndael.sub_bytes(c_block, 0)
        c_result = bytes(c_block.raw[:16])
        
        py_result = bytes([aes.s_box[b] for b in test_block])
        
        if c_result == py_result:
            print(f"  Test {test_num + 1}: PASS")
            passed += 1
        else:
            print(f"  Test {test_num + 1}: FAIL")
            print(f"    Input:    {test_block.hex()}")
            print(f"    C output: {c_result.hex()}")
            print(f"    Expected: {py_result.hex()}")
            failed += 1
    
    print(f"\nsub_bytes: {passed} passed, {failed} failed\n")
    return failed == 0

def test_invert_sub_bytes():
    """Test the invert_sub_bytes function"""
    print("Testing invert_sub_bytes...")
    
    import random
    random.seed(43)
    
    passed = 0
    failed = 0
    
    for test_num in range(3):
        test_block = bytes([random.randint(0, 255) for _ in range(16)])
        
        c_block = ctypes.create_string_buffer(test_block, 16)
        rijndael.invert_sub_bytes(c_block, 0)
        c_result = bytes(c_block.raw[:16])
        
        py_result = bytes([aes.inv_s_box[b] for b in test_block])
        
        if c_result == py_result:
            print(f"  Test {test_num + 1}: PASS")
            passed += 1
        else:
            print(f"  Test {test_num + 1}: FAIL")
            print(f"    Input:    {test_block.hex()}")
            print(f"    C output: {c_result.hex()}")
            print(f"    Expected: {py_result.hex()}")
            failed += 1
    
    print(f"\ninvert_sub_bytes: {passed} passed, {failed} failed\n")
    return failed == 0

def test_add_round_key():
    """Test the add_round_key function"""
    print("Testing add_round_key...")
    
    import random
    random.seed(44)
    
    passed = 0
    failed = 0
    
    for test_num in range(3):
        test_block = bytes([random.randint(0, 255) for _ in range(16)])
        test_key = bytes([random.randint(0, 255) for _ in range(16)])
        
        c_block = ctypes.create_string_buffer(test_block, 16)
        c_key = ctypes.create_string_buffer(test_key, 16)
        rijndael.add_round_key(c_block, c_key, 0)
        c_result = bytes(c_block.raw[:16])
        
        py_result = bytes([a ^ b for a, b in zip(test_block, test_key)])
        
        if c_result == py_result:
            print(f"  Test {test_num + 1}: PASS")
            passed += 1
        else:
            print(f"  Test {test_num + 1}: FAIL")
            print(f"    Block:    {test_block.hex()}")
            print(f"    Key:      {test_key.hex()}")
            print(f"    C output: {c_result.hex()}")
            print(f"    Expected: {py_result.hex()}")
            failed += 1
    
    print(f"\nadd_round_key: {passed} passed, {failed} failed\n")
    return failed == 0

def test_shift_rows():
    """Test the shift_rows function"""
    print("Testing shift_rows...")
    
    import random
    random.seed(45)
    
    passed = 0
    failed = 0
    
    for test_num in range(3):
        test_matrix = [[random.randint(0, 255) for _ in range(4)] for _ in range(4)]
        test_block = bytes([test_matrix[row][col] for row in range(4) for col in range(4)])
        
        c_block = ctypes.create_string_buffer(test_block, 16)
        rijndael.shift_rows(c_block, 0)
        c_result = bytes(c_block.raw[:16])
        
        expected = bytearray(16)
        for row in range(4):
            for col in range(4):
                expected[row * 4 + col] = test_matrix[row][(col + row) % 4]
        
        if c_result == bytes(expected):
            print(f"  Test {test_num + 1}: PASS")
            passed += 1
        else:
            print(f"  Test {test_num + 1}: FAIL")
            failed += 1
    
    print(f"\nshift_rows: {passed} passed, {failed} failed\n")
    return failed == 0

def test_invert_shift_rows():
    """Test the invert_shift_rows function"""
    print("Testing invert_shift_rows...")
    
    import random
    random.seed(46)
    
    passed = 0
    failed = 0
    
    for test_num in range(3):
        test_matrix = [[random.randint(0, 255) for _ in range(4)] for _ in range(4)]
        test_block = bytes([test_matrix[row][col] for row in range(4) for col in range(4)])
        
        c_block = ctypes.create_string_buffer(test_block, 16)
        rijndael.shift_rows(c_block, 0)
        rijndael.invert_shift_rows(c_block, 0)
        c_result = bytes(c_block.raw[:16])
        
        if c_result == test_block:
            print(f"  Test {test_num + 1}: PASS")
            passed += 1
        else:
            print(f"  Test {test_num + 1}: FAIL")
            failed += 1
    
    print(f"\ninvert_shift_rows: {passed} passed, {failed} failed\n")
    return failed == 0

def test_mix_columns():
    """Test the mix_columns function"""
    print("Testing mix_columns...")
    
    import random
    random.seed(47)
    
    passed = 0
    failed = 0
    
    for test_num in range(3):
        # Generate random block
        test_block = bytes([random.randint(0, 255) for _ in range(16)])
        
        # Apply mix_columns with C implementation
        c_block = ctypes.create_string_buffer(test_block, 16)
        rijndael.mix_columns(c_block, 0)
        c_result = bytes(c_block.raw[:16])
        
        # Now apply inverse to verify it's working correctly
        # (mix_columns and invert_mix_columns should be inverses)
        c_block2 = ctypes.create_string_buffer(c_result, 16)
        rijndael.invert_mix_columns(c_block2, 0)
        c_reversed = bytes(c_block2.raw[:16])
        
        # The reversed result should match original
        if c_reversed == test_block:
            print(f"  Test {test_num + 1}: PASS")
            passed += 1
        else:
            print(f"  Test {test_num + 1}: FAIL")
            print(f"    Original: {test_block.hex()}")
            print(f"    After mix and unmix: {c_reversed.hex()}")
            failed += 1
    
    print(f"\nmix_columns: {passed} passed, {failed} failed\n")
    return failed == 0

def test_invert_mix_columns():
    """Test the invert_mix_columns function"""
    print("Testing invert_mix_columns...")
    
    import random
    random.seed(48)
    
    passed = 0
    failed = 0
    
    for test_num in range(3):
        test_block = bytes([random.randint(0, 255) for _ in range(16)])
        
        c_block = ctypes.create_string_buffer(test_block, 16)
        rijndael.mix_columns(c_block, 0)
        rijndael.invert_mix_columns(c_block, 0)
        c_result = bytes(c_block.raw[:16])
        
        if c_result == test_block:
            print(f"  Test {test_num + 1}: PASS")
            passed += 1
        else:
            print(f"  Test {test_num + 1}: FAIL")
            failed += 1
    
    print(f"\ninvert_mix_columns: {passed} passed, {failed} failed\n")
    return failed == 0

def test_full_encryption_decryption():
    """Test the complete encryption and decryption"""
    print("Testing full encryption and decryption...")
    
    import random
    random.seed(100)
    
    passed = 0
    failed = 0
    
    for test_num in range(3):
        plaintext = bytes([random.randint(0, 255) for _ in range(16)])
        key = bytes([random.randint(0, 255) for _ in range(16)])
        
        c_plaintext = ctypes.create_string_buffer(plaintext, 16)
        c_key = ctypes.create_string_buffer(key, 16)
        
        rijndael.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)
        rijndael.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)
        
        c_ciphertext_ptr = rijndael.aes_encrypt_block(c_plaintext, c_key, 0)
        c_ciphertext = bytes(ctypes.cast(c_ciphertext_ptr, ctypes.POINTER(ctypes.c_ubyte * 16)).contents)
        
        c_ciphertext_buf = ctypes.create_string_buffer(c_ciphertext, 16)
        c_decrypted_ptr = rijndael.aes_decrypt_block(c_ciphertext_buf, c_key, 0)
        c_decrypted = bytes(ctypes.cast(c_decrypted_ptr, ctypes.POINTER(ctypes.c_ubyte * 16)).contents)
        
        if c_decrypted == plaintext:
            print(f"  Test {test_num + 1}: PASS")
            passed += 1
        else:
            print(f"  Test {test_num + 1}: FAIL")
            print(f"    Plaintext:  {plaintext.hex()}")
            print(f"    Ciphertext: {c_ciphertext.hex()}")
            print(f"    Decrypted:  {c_decrypted.hex()}")
            failed += 1
    
    print(f"\nfull encryption/decryption: {passed} passed, {failed} failed\n")
    return failed == 0

def test_encryption_256bit():
    """Test encryption with 256-bit blocks"""
    print("Testing 256-bit encryption...")
    
    import random
    random.seed(200)
    
    plaintext = bytes([random.randint(0, 255) for _ in range(32)])
    key = bytes([random.randint(0, 255) for _ in range(32)])
    
    c_plaintext = ctypes.create_string_buffer(plaintext, 32)
    c_key = ctypes.create_string_buffer(key, 32)
    
    rijndael.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)
    rijndael.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)
    
    c_ciphertext_ptr = rijndael.aes_encrypt_block(c_plaintext, c_key, 1)  # 1 = AES_BLOCK_256
    c_ciphertext = bytes(ctypes.cast(c_ciphertext_ptr, ctypes.POINTER(ctypes.c_ubyte * 32)).contents)
    
    c_ciphertext_buf = ctypes.create_string_buffer(c_ciphertext, 32)
    c_decrypted_ptr = rijndael.aes_decrypt_block(c_ciphertext_buf, c_key, 1)
    c_decrypted = bytes(ctypes.cast(c_decrypted_ptr, ctypes.POINTER(ctypes.c_ubyte * 32)).contents)
    
    if c_decrypted == plaintext:
        print("  256-bit test: PASS\n")
        return True
    else:
        print("  256-bit test: FAIL\n")
        return False

if __name__ == "__main__":
    print("="*60)
    print("AES Implementation Unit Tests")
    print("="*60 + "\n")
    
    all_passed = True
    
    all_passed &= test_sub_bytes()
    all_passed &= test_invert_sub_bytes()
    all_passed &= test_add_round_key()
    all_passed &= test_shift_rows()
    all_passed &= test_invert_shift_rows()
    all_passed &= test_mix_columns()
    all_passed &= test_invert_mix_columns()
    all_passed &= test_full_encryption_decryption()
    
    print("="*60)
    if all_passed:
        print("ALL TESTS PASSED!")
        sys.exit(0)
    else:
        print("SOME TESTS FAILED")
        sys.exit(1)