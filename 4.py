import struct
import os

BS = 8

def pad(data):
    n = BS - (len(data) % BS)
    return data + bytes([n])*n

def unpad(data):
    if not data: return data
    n = data[-1]
    return data[:-n]

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def simple_blowfish_block_encrypt(block, key):
    k = sum(key) % 256
    return bytes((b + k) % 256 for b in block)

def simple_blowfish_block_decrypt(block, key):
    k = sum(key) % 256
    return bytes((b - k) % 256 for b in block)

def encrypt(key, plaintext):
    plaintext = pad(plaintext)
    iv = os.urandom(BS)
    ciphertext = b""
    prev = iv
    for i in range(0, len(plaintext), BS):
        block = plaintext[i:i+BS]
        block = xor_bytes(block, prev)
        block = simple_blowfish_block_encrypt(block, key)
        ciphertext += block
        prev = block
    return iv + ciphertext

def decrypt(key, ciphertext):
    iv = ciphertext[:BS]
    ciphertext = ciphertext[BS:]
    plaintext = b""
    prev = iv
    for i in range(0, len(ciphertext), BS):
        block = ciphertext[i:i+BS]
        decrypted = simple_blowfish_block_decrypt(block, key)
        decrypted = xor_bytes(decrypted, prev)
        plaintext += decrypted
        prev = block
    return unpad(plaintext)


if __name__ == "__main__":
    key = b"Goodbyeworld!"
    text = b"Hello World!"

    ct = encrypt(key, text)
    print("Зашифрований (hex):", ct.hex())

    pt = decrypt(key, ct)
    print("Розшифрований:", pt.decode())

if __name__ == "__main__":
    import unittest

    class TestBlowfish(unittest.TestCase):
        def test_encrypt_decrypt_text(self):
            key = b"mysecret"
            text = b"Hello, world!"
            ct = encrypt(key, text)
            pt = decrypt(key, ct)
            self.assertEqual(pt, text)

        def test_encrypt_different_iv(self):
            key = b"mysecret"
            text = b"Some secret data"
            ct1 = encrypt(key, text)
            ct2 = encrypt(key, text)
            self.assertNotEqual(ct1, ct2)
    unittest.main()

