from swiftCrypt import fileTransform 


swift_crypt = fileTransform()



input_file = 'plaintext.txt'
encrypted_file = 'encrypted_file.bin'
decrypted_file = 'decrypted_file.txt'

password = "your_password_here"  # Replace with your password

# Encrypt the file
swift_crypt.encrypt_file(input_file, encrypted_file, password)

# Decrypt the file
swift_crypt.decrypt_file(encrypted_file, decrypted_file, password)

print("File encryption and decryption completed.")