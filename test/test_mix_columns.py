import ctypes
import unittest

rijndael = ctypes.CDLL('./rijndael.so')
rijndael.mix_columns.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]

class TestMixColumns(unittest.TestCase):
    def test_known_input(self):
        input_block = [
            0xdb, 0x13, 0x53, 0x45,
            0xf2, 0x0a, 0x22, 0x5c,
            0x01, 0x01, 0x01, 0x01,
            0xc6, 0xc6, 0xc6, 0xc6
        ]

        expected_output = [
            0x8e, 0x4d, 0xa1, 0xbc,
            0x9f, 0xdc, 0x58, 0x9d,
            0x01, 0x01, 0x01, 0x01,
            0xc6, 0xc6, 0xc6, 0xc6
        ]

        block = (ctypes.c_ubyte * 16)(*input_block)
        rijndael.mix_columns(block)
        result = list(block)

        self.assertEqual(result, expected_output)

if __name__ == '__main__':
    unittest.main()