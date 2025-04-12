import ctypes
import unittest

# Load the compiled C shared library
rijndael = ctypes.CDLL('./rijndael.so')

# Set argument types for safety
rijndael.sub_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]

class TestSubBytes(unittest.TestCase):
    def test_sub_bytes_with_known_input(self):
        # Step 1: Define input block (16 bytes)
        input_data = [
            0x00, 0x01, 0x02, 0x03,
            0x10, 0x11, 0x12, 0x13,
            0x20, 0x21, 0x22, 0x23,
            0x30, 0x31, 0x32, 0x33
        ]

        # Step 2: Expected output using standard AES S-box
        expected_output = [
            0x63, 0x7C, 0x77, 0x7B,
            0xCA, 0x82, 0xC9, 0x7D,
            0xB7, 0xFD, 0x93, 0x26,
            0x04, 0xC7, 0x23, 0xC3
        ]

        # Step 3: Convert input to C array
        c_block = (ctypes.c_ubyte * 16)(*input_data)

        # Step 4: Call the C function
        rijndael.sub_bytes(c_block)

        # Step 5: Convert result to Python list for assertion
        result = list(c_block)

        # Step 6: Compare result to expected output
        self.assertEqual(result, expected_output)

if __name__ == '__main__':
    unittest.main()