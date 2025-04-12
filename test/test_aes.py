import ctypes
import unittest

# Load C library
aes = ctypes.CDLL('./rijndael.so')

# Define the function signature
aes.sub_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]

class TestSubBytes(unittest.TestCase):
    def test_known_input(self):
        # Input block (16 bytes)
        input_data = [
            0x00, 0x01, 0x02, 0x03,
            0x10, 0x11, 0x12, 0x13,
            0x20, 0x21, 0x22, 0x23,
            0x30, 0x31, 0x32, 0x33
        ]

        expected_output = [
            0x63, 0x7c, 0x77, 0x7b,
            0xca, 0x82, 0xc9, 0x7d,
            0xb7, 0xfd, 0x93, 0x26,
            0x04, 0xc7, 0x23, 0xc3
        ]

        # Create C buffer
        block = (ctypes.c_ubyte * 16)(*input_data)

        # Call sub_bytes in C
        aes.sub_bytes(block)

        # Read back and compare
        result = list(block)
        self.assertEqual(result, expected_output)

if __name__ == '__main__':
    unittest.main()
