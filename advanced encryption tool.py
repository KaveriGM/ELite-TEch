import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import urlsafe_b64encode, urlsafe_b64decode
from getpass import getpass

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as file:
        data = file.read()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(file_path + '.enc', 'wb') as file:
        file.write(salt + iv + encrypted_data)
    print("File encrypted successfully.")

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as file:
        data = file.read()

    salt = data[:16]
    iv = data[16:32]
    encrypted_data = data[32:]
    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    with open(file_path[:-4], 'wb') as file:
        file.write(unpadded_data)
    print("File decrypted successfully.")

def main():
    while True:
        choice = input("Choose an option: [1] Encrypt a file, [2] Decrypt a file, [3] Exit: ")
        if choice == '1':
            file_path = input("Enter the path of the file to encrypt: ")
            password = getpass("Enter the encryption password: ")
            encrypt_file(file_path, password)
        elif choice == '2':
            file_path = input("Enter the path of the file to decrypt (with .enc extension): ")
            password = getpass("Enter the decryption password: ")
            decrypt_file(file_path, password)
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid option. Please choose again.")

if __name__ == "__main__":
    main()
