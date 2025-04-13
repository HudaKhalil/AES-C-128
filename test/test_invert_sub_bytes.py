import ctypes
import unittest

rijndael = ctypes.CDLL('./rijndael.so')

# Set argument type
rijndael.invert_sub_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]

class TestInvertSubBytes(unittest.TestCase):
    def test_invert_sub_bytes(self):
        # This input was originally transformed by sub_bytes
        input_after_sub = [
            0x63, 0x7c, 0x77, 0x7b,
            0xca, 0x82, 0xc9, 0x7d,
            0xb7, 0xfd, 0x93, 0x26,
            0x04, 0xc7, 0x23, 0xc3
        ]
        # Expected result is the original plaintext before sub_bytes
        expected_original = [
            0x00, 0x01, 0x02, 0x03,
            0x10, 0x11, 0x12, 0x13,
            0x20, 0x21, 0x22, 0x23,
            0x30, 0x31, 0x32, 0x33
        ]

        block = (ctypes.c_ubyte * 16)(*input_after_sub)
        rijndael.invert_sub_bytes(block)
        result = list(block)

        self.assertEqual(result, expected_original)

if __name__ == '__main__':
    unittest.main()