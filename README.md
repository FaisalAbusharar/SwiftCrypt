<p align="center">
  <img src="https://raw.githubusercontent.com/Tech-Tweaks/SwiftCrypt/main/swiftCrypt.png" alt="SwiftCrypt Logo">
</p>

<h1 align="center">SwiftCrypt</h1>

<p align="center">
  <b>A Versatile Python module to streamline security tasks, allowing you to concentrate on your core program</b>
</p>

<p align="center">
  <b>Please note: this isn't some new top-notch security, it simply reduces the amount of work you need to put in for security, so you can focus on your actual program!</b>
</p>

<p align="center">
  <a href="https://pypi.org/project/swiftcrypt/"><img src="https://img.shields.io/pypi/status/swiftcrypt" alt="Status"></a>
  <a href="https://www.python.org/downloads/release"><img src="https://img.shields.io/pypi/pyversions/swiftcrypt" alt="Python Version"></a>
  <a href="https://pypi.org/project/swiftcrypt/"><img src="https://img.shields.io/pypi/v/swiftcrypt" alt="Version"></a>
  <a href="https://pypi.org/project/swiftcrypt/"><img src="https://img.shields.io/pypi/dw/swiftcrypt" alt="Downloads"></a>
</p>

#### Documentation isn't out yet. please check the 'swiftcrypt' folder, and each class has its own file explaning the functions!


## Features

- **Secret Generation:** Create random secrets, keys, UUIDs, and passwords using various character sets and customizable configurations.
- **Data Transformation:** Encode and decode data with Base64 and hexadecimal. Securely erase sensitive data using random bytes.
- **Advanced Generation:** Tailor key and password generation with options for uppercase, dual cases, and more.
- **Password Strength Checker:** Evaluate password strength based on length, character types, and more.
- **Password Hashing:** Hash passwords using the any algorithm avaliable with advanced salting.
- **Salt Generation:** Generate unique salts for enhanced password security.
- **Two-Factor Authentication (2FA):** Generate QR codes for 2FA setup, verify TOTP codes, and send QR codes via email.


## Installation

Install SwiftCrypt using `pip`:

```bash
pip install swiftcrypt
```
# Usage
Here's a quick example of some of the features SwiftCrypt has.

```python
from swiftcrypt import SecretGenerator, Checker, Hash, Salts, fileTransform, rateLimiter

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

# Create an instance of RateLimiter
rate_limiter = RateLimiter()

# Simulate a login attempt and rate limiting
user_id = "user123"
ip_address = "123.456.789.0"

if rate_limiter.check_rate_limit(user_id, ip_address):
    print("Login allowed.")
    # Perform the login logic here
    # ...
else:
    print("Rate limit exceeded. Please wait before trying again.")
    rate_limiter.record_failed_attempt(f"{user_id}_{ip_address}")


```

# Using the new 2FA

```python

from swiftcrypt import TwoFactorAuth

two_factor_auth = TwoFactorAuth()

# Generate a secret key for 2FA
user_secret_key = two_factor_auth.generate_secret_key()

# Generate a QR code image for 2FA setup
user_qr_code = two_factor_auth.generate_qr_code(user_secret_key, "user@example.com")

# Send the QR code via email
two_factor_auth.send_qr_code_email(user_qr_code, "user@example.com", "your_email@gmail.com", "your_email_password")

# Print the QR code as a base64-encoded string
two_factor_auth.generate_qr_code_and_print("user@example.com")
```



Check out our documentation for more detailed instructions and examples. [COMING SOON]

# Contribution
We welcome contributions! If you encounter issues or want to enhance SwiftCrypt, please submit a pull request or open an issue.

Discord: https://discord.gg/dtGT6qryUR

# License
SwiftCrypt is licensed under the MIT License.

Feel free to integrate SwiftCrypt into your projects to simplify security tasks and focus on your core development. If you have queries or need assistance, do not hesitate to get in touch.

