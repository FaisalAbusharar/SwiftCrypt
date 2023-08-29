from swiftcrypt import SecureFileHandler
from cryptography.fernet import Fernet

# Recreate the encryption key
encryption_key = Fernet.generate_key()

# Use the recreated encryption key to initialize the SecureFileHandler
file_handler = SecureFileHandler(encryption_key)

# Encrypt and upload a file
hash_value = file_handler.encrypt_and_upload_file('file.txt', 'encrypted_file.enc')


# Download and decrypt the file
file_handler.download_and_decrypt_file('encrypted_file.enc', 'decrypted_file.txt', hash_value)