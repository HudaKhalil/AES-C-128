import ctypes
import unittest
import random
from Crypto.Cipher import AES

# Load your compiled C shared library
rijndael = ctypes.CDLL('./rijndael.so')

# Define argument and return types for AES functions
rijndael.aes_encrypt_block.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_ubyte)
]
rijndael.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)

rijndael.aes_decrypt_block.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_ubyte)
]
rijndael.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)

class TestAesEncryptDecryptFull(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        for i in range(3):  # Repeat 3 times for 3 random inputs
            with self.subTest(round=i + 1):
                # Generate random key and plaintext
                key_bytes = bytes(random.randint(0, 255) for _ in range(16))
                plaintext_bytes = bytes(random.randint(0, 255) for _ in range(16))

                # Encrypt with Python (PyCryptodome)
                py_cipher = AES.new(key_bytes, AES.MODE_ECB)
                py_ciphertext = py_cipher.encrypt(plaintext_bytes)

                # Encrypt with C
                key_c = (ctypes.c_ubyte * 16)(*key_bytes)
                plaintext_c = (ctypes.c_ubyte * 16)(*plaintext_bytes)
                c_cipher_ptr = rijndael.aes_encrypt_block(plaintext_c, key_c)
                c_cipher = ctypes.string_at(c_cipher_ptr, 16)

                # Step 1: Compare ciphertexts (C vs Python)
                self.assertEqual(
                    c_cipher, py_ciphertext,
                    msg=f"Encryption mismatch on round {i+1}"
                )

                # Decrypt with C
                c_cipher_buffer = (ctypes.c_ubyte * 16)(*c_cipher)
                decrypted_ptr = rijndael.aes_decrypt_block(c_cipher_buffer, key_c)
                decrypted_plaintext = ctypes.string_at(decrypted_ptr, 16)

                # Step 2: Compare decrypted result with original
                self.assertEqual(
                    decrypted_plaintext, plaintext_bytes,
                    msg=f"Decryption mismatch on round {i+1}"
                )

if __name__ == '__main__':
    unittest.main()