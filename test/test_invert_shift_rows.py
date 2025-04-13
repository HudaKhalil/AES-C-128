import ctypes
import unittest

rijndael = ctypes.CDLL('./rijndael.so')

# Define argument type
rijndael.invert_shift_rows.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]

class TestInvertShiftRows(unittest.TestCase):
    def test_invert_shift_rows(self):
        # This block has already been shifted by shift_rows during encryption
        shifted = [
            0x00, 0x05, 0x0A, 0x0F,   # Row 0 (unchanged)
            0x04, 0x09, 0x0E, 0x03,   # Row 1: was left-shifted by 1
            0x08, 0x0D, 0x02, 0x07,   # Row 2: was left-shifted by 2
            0x0C, 0x01, 0x06, 0x0B    # Row 3: was left-shifted by 3
        ]

        # Expected to return to this (original before encryption)
        expected = [
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F
        ]

        block = (ctypes.c_ubyte * 16)(*shifted)
        rijndael.invert_shift_rows(block)
        result = list(block)

        self.assertEqual(result, expected)

if __name__ == '__main__':
    unittest.main()