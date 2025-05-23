
import os
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import getpass

def decrypt_file(file_path, password):
    backend = default_backend()
    with open(file_path, 'rb') as f:
        file_data = f.read()

    salt = file_data[:16]
    iv = file_data[16:32]
    encrypted_data = file_data[32:]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    key = kdf.derive(password.encode())

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    output_file = file_path.replace('.enc', '') + '.dec'
    with open(output_file, 'wb') as f:
        f.write(data)

    print(f"Decrypted file saved as {output_file}")

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 2:
        print("Usage: python decrypt.py <encrypted_file_path>")
        sys.exit(1)
    password = getpass.getpass("Enter password: ")
    decrypt_file(sys.argv[1], password)
