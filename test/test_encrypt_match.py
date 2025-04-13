import ctypes
import unittest
import random
from Crypto.Cipher import AES

rijndael = ctypes.CDLL('./rijndael.so')
rijndael.aes_encrypt_block.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_ubyte)
]
rijndael.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)

class TestEncryptAgainstPyCrypto(unittest.TestCase):
    def test_match_pycryptodome(self):
        # Generate random 16-byte key and plaintext
        key_bytes = bytes(random.randint(0, 255) for _ in range(16))
        plaintext_bytes = bytes(random.randint(0, 255) for _ in range(16))

        # --- Python encryption using PyCryptodome ---
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        expected_ciphertext = cipher.encrypt(plaintext_bytes)

        # --- C encryption using your shared object ---
        key = (ctypes.c_ubyte * 16)(*key_bytes)
        plaintext = (ctypes.c_ubyte * 16)(*plaintext_bytes)

        result_ptr = rijndael.aes_encrypt_block(plaintext, key)
        result_ciphertext = ctypes.string_at(result_ptr, 16)

        # Assert they match
        self.assertEqual(result_ciphertext, expected_ciphertext)

if __name__ == '__main__':
    unittest.main()
