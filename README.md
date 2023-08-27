<p align="center">
  <img src="swiftCrypt.png" alt="SwiftCrypt Logo">
</p>

<h1 align="center">SwiftCrypt</h1>

<p align="center">
  <b>Versatile Python module for enhanced security utilities</b>
</p>

<p align="center">
  <a href="https://pypi.org/project/swiftcrypt/"><img src="https://img.shields.io/pypi/status/swiftcrypt" alt="Status"></a>
  <a href="https://www.python.org/downloads/release"><img src="https://img.shields.io/pypi/pyversions/swiftcrypt" alt="Python Version"></a>
  <a href="https://pypi.org/project/swiftcrypt/"><img src="https://img.shields.io/pypi/v/swiftcrypt" alt="Version"></a>
</p>

### Documentation isn't out yet. please check the 'swiftcrypt' folder, and each class has its own file explaning the functions!


## Features

- **Secret Generation:** Create random secrets, keys, UUIDs, and passwords using various character sets and customizable configurations.
- **Data Transformation:** Encode and decode data with Base64 and hexadecimal. Securely erase sensitive data using random bytes.
- **Advanced Generation:** Tailor key and password generation with options for uppercase, dual cases, and more.
- **Password Strength Checker:** Evaluate password strength based on length, character types, and more.
- **Password Hashing:** Hash passwords using the any algorithm avaliable with advanced salting.
- **Salt Generation:** Generate unique salts for enhanced password security.

## Installation

Install SwiftCrypt using `pip`:

```bash
pip install swiftcrypt
```
# Usage
Here's a quick example of some of the features SwiftCrypt has.

```python
from swiftcrypt import SecretGenerator, Checker, Hash, Salts, fileTransform

# Create an instance of SecretGenerator
generator = SecretGenerator()

# Generate a secure password
password = generator.generate_password(length=12, numbers=True, special_characters=True)
print("Generated Password:", password)

# Create an instance of Checker
password_checker = Checker()

# Check the strength of a password
strength = password_checker.check_password_strength(password)
print("Password Strength:", strength)

# Create an instance of Hash
hasher = Hash()

# Hash a password with a salt
salt = Salts().generate_salt()
hashed_password = hasher.hash_password(password, salt)
print("Hashed Password:", hashed_password)

# Verify a password against a hashed password
is_verified = password_checker.verify_password(password, hashed_password, salt)
print("Password Verified:", is_verified)

# Create an instance of Salts
salts = Salts()

# Generate a salt and estimate its entropy
new_salt = salts.generate_salt()
entropy = salts.estimate_entropy(new_salt)
print("Generated Salt:", new_salt)
print("Estimated Entropy:", entropy)

# Create an instance of fileTransform
file_transformer = fileTransform()

# Encrypt a file
file_transformer.encrypt_file("plaintext.txt", "encrypted.bin", password)

# Decrypt the encrypted file
file_transformer.decrypt_file("encrypted.bin", "decrypted.txt", password)

```
Check out our documentation for more detailed instructions and examples.

# Contribution
We welcome contributions! If you encounter issues or want to enhance SwiftCrypt, please submit a pull request or open an issue.
Discord: https://discord.gg/dtGT6qryUR

# License
SwiftCrypt is licensed under the MIT License.

Feel free to use SwiftCrypt in your projects and enjoy a safer development experience! If you have any questions or need assistance, please don't hesitate to reach out.

