import unittest
from Blowfish import encrypt, decrypt


class TestBlowfish(unittest.TestCase):

    def setUp(self):
        self.key = b"secretkey"
        self.message = b"Hello Blowfish"

    def test_encrypt_decrypt(self):
        encrypted = encrypt(self.message, self.key)
        decrypted = decrypt(encrypted, self.key)
        self.assertEqual(decrypted, self.message)

    def test_wrong_key(self):
        encrypted = encrypt(self.message, self.key)
        with self.assertRaises(ValueError):
            decrypt(encrypted, b"wrongkey")


if __name__ == "__main__":
    unittest.main()
