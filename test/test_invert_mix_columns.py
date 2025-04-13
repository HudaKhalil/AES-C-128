import ctypes
import unittest

rijndael = ctypes.CDLL('./rijndael.so')

# Define argument type
rijndael.invert_mix_columns.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]

class TestInvertMixColumns(unittest.TestCase):
    def test_invert_mix_columns(self):
        # This is the result AFTER mix_columns was applied to the original input
        mixed = [
            0x8e, 0x4d, 0xa1, 0xbc,
            0x9f, 0xdc, 0x58, 0x9d,
            0x01, 0x01, 0x01, 0x01,
            0xc6, 0xc6, 0xc6, 0xc6
        ]

        # This was the input BEFORE mix_columns (i.e. original state)
        expected = [
            0xdb, 0x13, 0x53, 0x45,
            0xf2, 0x0a, 0x22, 0x5c,
            0x01, 0x01, 0x01, 0x01,
            0xc6, 0xc6, 0xc6, 0xc6
        ]

        block = (ctypes.c_ubyte * 16)(*mixed)
        rijndael.invert_mix_columns(block)
        result = list(block)

        self.assertEqual(result, expected)

if __name__ == '__main__':
    unittest.main()