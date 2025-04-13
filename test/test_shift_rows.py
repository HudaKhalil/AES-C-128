import ctypes
import unittest

# Load the C shared library
aes = ctypes.CDLL('./rijndael.so')

aes.shift_rows.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]

class TestShiftRows(unittest.TestCase):
    def test_shift_rows(self):
        # Input block: row-wise layout
        input_data = [
            0, 1, 2, 3,
            4, 5, 6, 7,
            8, 9,10,11,
            12,13,14,15
        ]

        expected_output = [
            0, 5,10,15,
            4, 9,14, 3,
            8,13, 2, 7,
            12, 1, 6,11
        ]

        # Because we're doing row-wise input, we reverse what is shown above
        input_data = [
            0, 1, 2, 3,
            4, 5, 6, 7,
            8, 9,10,11,
            12,13,14,15
        ]

        expected_output = [
            0, 5,10,15,
            4, 9,14, 3,
            8,13, 2, 7,
            12, 1, 6,11
        ]

        block = (ctypes.c_ubyte * 16)(*input_data)
        aes.shift_rows(block)
        self.assertEqual(list(block), expected_output)

if __name__ == '__main__':
    unittest.main()