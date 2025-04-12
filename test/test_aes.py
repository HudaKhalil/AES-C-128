import ctypes
from ctypes import c_char_p, create_string_buffer
from ctypes import string_at
import os
import sys
# Add the AES Python submodule to the path
sys.path.append('./python-aes')


# Load the compiled shared C library
lib = ctypes.CDLL('./rijndael.so')

# Define argument and return types
lib.aes_encrypt_block.argtypes = [c_char_p, c_char_p]
lib.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte * 16)

lib.aes_decrypt_block.argtypes = [c_char_p, c_char_p]
lib.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte * 16)

def test_encrypt_decrypt():
    for i in range(3):
        print(f"--- Test case {i+1} ---")
        plaintext = os.urandom(16)
        key = os.urandom(16)

        # Python reference AES encryption
        py_ciphertext = aes.encrypt_block(list(plaintext), list(key))

        # C implementation encryption
        pt_buf = create_string_buffer(plaintext)
        key_buf = create_string_buffer(key)
        c_ciphertext = bytes(lib.aes_encrypt_block(pt_buf, key_buf).contents)

        assert bytes(py_ciphertext) == c_ciphertext, "Mismatch in ciphertext!"

        # C implementation decryption
        ct_buf = create_string_buffer(c_ciphertext)
        recovered_pt = bytes(lib.aes_decrypt_block(ct_buf, key_buf).contents)

        assert recovered_pt == plaintext, "Mismatch in recovered plaintext!"

        print("✔ Encryption and decryption match!")

if __name__ == "__main__":
    test_encrypt_decrypt()