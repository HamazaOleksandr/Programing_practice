from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


def encrypt(data: bytes, key: bytes) -> bytes:
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, Blowfish.block_size))
    return cipher.iv + ciphertext


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    iv = ciphertext[:Blowfish.block_size]
    data = ciphertext[Blowfish.block_size:]
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(data), Blowfish.block_size)


if __name__ == "__main__":
    key = b"sonnycrocket"
    message = b"Ferrari Testarossa"

    encrypted = encrypt(message, key)
    decrypted = decrypt(encrypted, key)

    print("Encrypted:", encrypted)
    print("Decrypted:", decrypted)
