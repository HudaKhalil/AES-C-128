import ctypes
import unittest
import random
from Crypto.Cipher import AES

# Load the compiled C library
rijndael = ctypes.CDLL('./rijndael.so')

# Set C function signatures
rijndael.aes_decrypt_block.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_ubyte)
]
rijndael.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)

class TestCDecryptAgainstPythonAES(unittest.TestCase):
    def test_decrypt_3_random_cases(self):
        for i in range(3):
            with self.subTest(round=i + 1):
                # Generate random key and plaintext
                key_bytes = bytes(random.randint(0, 255) for _ in range(16))
                plaintext_bytes = bytes(random.randint(0, 255) for _ in range(16))

                # Encrypt using Pythons PyCryptodome
                cipher = AES.new(key_bytes, AES.MODE_ECB)
                ciphertext = cipher.encrypt(plaintext_bytes)

                # Decrypt using your C function
                key = (ctypes.c_ubyte * 16)(*key_bytes)
                ciphertext_c = (ctypes.c_ubyte * 16)(*ciphertext)

                pt_ptr = rijndael.aes_decrypt_block(ciphertext_c, key)
                decrypted_bytes = ctypes.string_at(pt_ptr, 16)

                # Compare C output with original plaintext
                self.assertEqual(decrypted_bytes, plaintext_bytes)

if __name__ == '__main__':
    unittest.main()
