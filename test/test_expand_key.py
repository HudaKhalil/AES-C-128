import ctypes
import unittest

rijndael = ctypes.CDLL('./rijndael.so')
rijndael.expand_key.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
rijndael.expand_key.restype = ctypes.POINTER(ctypes.c_ubyte)

class TestExpandKey(unittest.TestCase):
    def test_round_keys_size(self):
        key = (ctypes.c_ubyte * 16)(*range(16))
        expanded = rijndael.expand_key(key)
        result = ctypes.string_at(expanded, 176)

        self.assertEqual(len(result), 176)

        # Optional: test first round key matches input key
        self.assertEqual(list(result[:16]), list(range(16)))

if __name__ == '__main__':
    unittest.main()