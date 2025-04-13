import ctypes
import unittest

rijndael = ctypes.CDLL('./rijndael.so')
rijndael.add_round_key.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte),
    ctypes.POINTER(ctypes.c_ubyte)
]

class TestAddRoundKey(unittest.TestCase):
    def test_simple_xor(self):
        block = [
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F
        ]

        key = [
            0x0F, 0x0E, 0x0D, 0x0C,
            0x0B, 0x0A, 0x09, 0x08,
            0x07, 0x06, 0x05, 0x04,
            0x03, 0x02, 0x01, 0x00
        ]

        expected = [
            0x0F, 0x0F, 0x0F, 0x0F,
            0x0F, 0x0F, 0x0F, 0x0F,
            0x0F, 0x0F, 0x0F, 0x0F,
            0x0F, 0x0F, 0x0F, 0x0F
        ]

        block_buf = (ctypes.c_ubyte * 16)(*block)
        key_buf = (ctypes.c_ubyte * 16)(*key)

        rijndael.add_round_key(block_buf, key_buf)

        result = list(block_buf)
        self.assertEqual(result, expected)

if __name__ == '__main__':
    unittest.main()