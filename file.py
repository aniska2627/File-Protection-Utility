
import os
import base64
import getpass
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# File format identifier
MAGIC = b"FPU1"

# Generate an encryption key from the password
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000
    )

    key = base64.urlsafe_b64encode(
        kdf.derive(password.encode())
    )

    return Fernet(key)


# Encrypt a file
def encrypt_file():
    file_name = input("Enter file path to encrypt: ").strip().strip('"')
    file_path = Path(file_name)

    if not file_path.is_file():
        print("Error: File not found!")
        return

    password = getpass.getpass("Create encryption password: ")
    confirm = getpass.getpass("Confirm password: ")

    if not password:
        print("Password cannot be empty!")
        return

    if password != confirm:
        print("Passwords do not match!")
        return

    output_path = file_path.with_name(file_path.name + ".locked")

    if output_path.exists():
        print("Error: Protected output file already exists!")
        return

    try:
        original_data = file_path.read_bytes()

        salt = os.urandom(16)
        cipher = generate_key(password, salt)

        encrypted_data = cipher.encrypt(original_data)

        with open(output_path, "wb") as file:
            file.write(MAGIC + salt + encrypted_data)

        print("\nFile encrypted successfully!")
        print("Protected file:", output_path)

    except OSError as error:
        print("File error:", error)


# Decrypt a file
def decrypt_file():
    file_name = input("Enter protected file path: ").strip().strip('"')
    file_path = Path(file_name)

    if not file_path.is_file():
        print("Error: File not found!")
        return

    password = getpass.getpass("Enter decryption password: ")

    try:
        protected_data = file_path.read_bytes()

        if len(protected_data) <= 20 or not protected_data.startswith(MAGIC):
            print("Error: Invalid protected file!")
            return

        salt = protected_data[4:20]
        encrypted_data = protected_data[20:]

        cipher = generate_key(password, salt)

        original_data = cipher.decrypt(encrypted_data)

        if file_path.name.endswith(".locked"):
            original_name = file_path.name[:-7]
            original_path = file_path.with_name(original_name)
        else:
            original_path = file_path

        output_path = original_path.with_name(
            original_path.stem + "_restored" + original_path.suffix
        )

        if output_path.exists():
            print("Error: Restored output file already exists!")
            return

        with open(output_path, "wb") as file:
            file.write(original_data)

        print("\nFile decrypted successfully!")
        print("Restored file:", output_path)

    except InvalidToken:
        print("Error: Incorrect password or corrupted file!")

    except OSError as error:
        print("File error:", error)


# Main menu
def main():
    while True:
        print("\n" + "=" * 45)
        print("          FILE PROTECTION UTILITY")
        print("=" * 45)

        print("1. Encrypt a File")
        print("2. Decrypt a File")
        print("3. Exit")

        choice = input("\nEnter your choice: ").strip()

        if choice == "1":
            encrypt_file()

        elif choice == "2":
            decrypt_file()

        elif choice == "3":
            print("Thank you for using File Protection Utility!")
            break

        else:
            print("Invalid choice! Please select 1, 2 or 3.")


if __name__ == "__main__":
    main()
