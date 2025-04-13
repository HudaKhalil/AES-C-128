import ctypes
import unittest

rijndael = ctypes.CDLL('./rijndael.so')
rijndael.aes_encrypt_block.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_ubyte)
]
rijndael.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)

class TestAesEncryptBlock(unittest.TestCase):
    def test_encrypt_output_length(self):
        plaintext = (ctypes.c_ubyte * 16)(*range(16))
        key = (ctypes.c_ubyte * 16)(*[
            0x2b, 0x28, 0xab, 0x09,
            0x7e, 0xae, 0xf7, 0xcf,
            0x15, 0xd2, 0x15, 0x4f,
            0x16, 0xa6, 0x88, 0x3c
        ])

        ciphertext_ptr = rijndael.aes_encrypt_block(plaintext, key)
        ciphertext = ctypes.string_at(ciphertext_ptr, 16)

        self.assertEqual(len(ciphertext), 16)

if __name__ == '__main__':
    unittest.main()