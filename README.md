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
- **Password Hashing:** Hash passwords using any algorithm available with advanced salting.
- **Salt Generation:** Generate unique salts for enhanced password security.
- **Two-Factor Authentication (2FA):** Generate QR codes for 2FA setup, verify TOTP codes, and send QR codes via email.
- **Rate Limiting:** Prevent abuse by implementing rate limiting for actions like login attempts.
- **Digital Signature:** Create and verify digital signatures for message authenticity and integrity.
- **Data Masking:** Mask sensitive data such as passwords to enhance security.
- **SecureInputHandler:** This class handles secure database queries, including creating tables, retrieving user information, and executing queries securely.
- **CGSR (Cryptographically:** Secure Random): This class provides a method to generate cryptographically secure random bytes, which can be crucial for creating secure tokens, keys, and other sensitive data.
- **SecureSecretStorage:** This class provides a way to securely store and retrieve secrets, such as usernames and passwords, using the keyring library.
- **SecureSessionManager:** This class manages user sessions securely, creating, validating, and ending sessions while keeping track of timestamps.


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



# Create an instance of fileTransform
file_transformer = fileTransform()

# Encrypt a file
file_transformer.encrypt_file("plaintext.txt", "encrypted.bin", password)

# Decrypt the encrypted file
file_transformer.decrypt_file("encrypted.bin", "decrypted.txt", password)


# Create an instance of DataMasking
data_masker = DataMasking()

# Mask sensitive data, such as passwords, to enhance security
original_text = "HelloGuyswelcomeback"
masked_text = data_masker.mask_data(original_text, masking_character="*", chars_to_mask=4)
print("Original Text:", original_text)
print("Masked Text:", masked_text)

# Create an instance of DigitalSignature
digital_signature = DigitalSignature()

# Generate an RSA key pair
private_key, public_key = digital_signature.generate_key_pair()

# Define the message to be signed
message = b"Hello, this is a message."

# Sign the message using the private key
signature = digital_signature.sign_message(private_key, message)

# Verify the signature using the public key and the original message
verification_result = digital_signature.verify_signature(public_key, message, signature)


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

