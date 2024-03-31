from base64 import b32hexencode
from os import path, urandom
from sys import argv, exit
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from zlib import compress, decompress


def encryption(bytes: bytes) -> bytes:
    try:
        key = urandom(32)

        nonce = urandom(12)

        cipher = AESGCM(key)

        ciphertext = cipher.encrypt(nonce, bytes, None)

        return nonce + ciphertext, key
    except Exception as e:
        print("Error occured... '{}'".format(e))


def decryption(ciphertext: bytes, key: bytes) -> str:
    try:
        nonce = ciphertext[:12]

        ciphertext = ciphertext[12:]

        cipher = AESGCM(key)

        plaintext = cipher.decrypt(nonce, ciphertext, None)

        return plaintext.decode("latin-1")
    except Exception as e:
        print("Error occured... '{}'".format(e))


if __name__ == "__main__":
    try:
        if len(argv) != 3:
            print(
                "Please specify the file to be AES encrypted and the output file correctly like this.\n'python aes_encrypt.py config.ini config.aes'\n'python aes_encrypt.py shellcode.bin shellcode.aes'"
            )
            exit(1)

        file = open(argv[1], "rb")

        file_data = file.read()

        print("Encrypting '{}'...".format(path.abspath(argv[1])))

        ciphertext, key = encryption(file_data)

        print("Key:", repr(key.hex()))

        print("Test Decrypting '{}'...".format(path.abspath(argv[2])))

        decryption(ciphertext, key)

        print("Compressing '{}'...".format(path.abspath(argv[1])))

        compressed_aes_data = compress(ciphertext)

        print("Test Decompressing '{}'...".format(path.abspath(argv[2])))

        decompress(compressed_aes_data)

        print("Writing to file '{}'...".format(path.abspath(argv[2])))

        with open(argv[2], "w", encoding="latin-1") as file:
            file.write(b32hexencode(compressed_aes_data).decode("latin-1"))

        print("Wrote encrypted data to '{}'.".format(path.abspath(argv[2])))
    except Exception as e:
        print("Error occured... '{}'".format(e))
