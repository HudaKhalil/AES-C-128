import ctypes
import unittest

rijndael = ctypes.CDLL('./rijndael.so')

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

class TestDecryptAES(unittest.TestCase):
    def test_round_trip(self):
        plaintext = bytes(range(16))
        key = bytes([
            0x2b, 0x28, 0xab, 0x09,
            0x7e, 0xae, 0xf7, 0xcf,
            0x15, 0xd2, 0x15, 0x4f,
            0x16, 0xa6, 0x88, 0x3c
        ])

        plaintext_c = (ctypes.c_ubyte * 16)(*plaintext)
        key_c = (ctypes.c_ubyte * 16)(*key)

        ct_ptr = rijndael.aes_encrypt_block(plaintext_c, key_c)
        ct_bytes = ctypes.string_at(ct_ptr, 16)

        ct_c = (ctypes.c_ubyte * 16)(*ct_bytes)
        pt_ptr = rijndael.aes_decrypt_block(ct_c, key_c)
        pt_bytes = ctypes.string_at(pt_ptr, 16)

        self.assertEqual(pt_bytes, plaintext)

if __name__ == '__main__':
    unittest.main()