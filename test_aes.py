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
    
    # Test with 3 random blocks
    import random
    random.seed(42)  # For reproducibility
    
    passed = 0
    failed = 0
    
    for test_num in range(3):
        # Generate random 16-byte block
        test_block = bytes([random.randint(0, 255) for _ in range(16)])
        
        # Test with C implementation
        c_block = ctypes.create_string_buffer(test_block)
        rijndael.sub_bytes(c_block, 0)  # 0 = AES_BLOCK_128
        c_result = bytes(c_block.raw)
        
        # Test with Python implementation
        # The Python implementation's s_box is the same as our sbox
        py_result = bytes([aes.s_box[b] for b in test_block])
        
        # Compare results
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
        # Generate random 16-byte block
        test_block = bytes([random.randint(0, 255) for _ in range(16)])
        
        # Test with C implementation
        c_block = ctypes.create_string_buffer(test_block)
        rijndael.invert_sub_bytes(c_block, 0)
        c_result = bytes(c_block.raw)
        
        # Test with Python implementation
        py_result = bytes([aes.inv_s_box[b] for b in test_block])
        
        # Compare results
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
        # Generate random 16-byte block and key
        test_block = bytes([random.randint(0, 255) for _ in range(16)])
        test_key = bytes([random.randint(0, 255) for _ in range(16)])
        
        # Test with C implementation
        c_block = ctypes.create_string_buffer(test_block)
        c_key = ctypes.create_string_buffer(test_key)
        rijndael.add_round_key(c_block, c_key, 0)
        c_result = bytes(c_block.raw)
        
        # Expected result (XOR)
        py_result = bytes([a ^ b for a, b in zip(test_block, test_key)])
        
        # Compare results
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

if __name__ == "__main__":
    print("="*60)
    print("AES Implementation Unit Tests")
    print("="*60 + "\n")
    
    all_passed = True
    
    # Test individual functions
    all_passed &= test_sub_bytes()
    all_passed &= test_invert_sub_bytes()
    all_passed &= test_add_round_key()
    
    print("="*60)
    if all_passed:
        print("ALL TESTS PASSED!")
        sys.exit(0)
    else:
        print("SOME TESTS FAILED")
        sys.exit(1)
