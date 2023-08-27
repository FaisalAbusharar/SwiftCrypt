
# SwiftCrypt

![SwiftCrypt Logo](swiftCrypt.png) <!-- Replace with your actual logo -->

**SwiftCrypt** is a versatile Python module that empowers your projects with a comprehensive suite of security utilities. From generating secrets to hashing passwords, SwiftCrypt simplifies complex security tasks, allowing you to focus on building secure applications.
Wanna know the best part? made only with core python libraries!

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-%3E%3D3.6-blue.svg)](https://www.python.org/downloads/release)

## Features

- **Secret Generation:** Create random secrets, keys, UUIDs, and passwords using various character sets and customizable configurations.
- **Data Transformation:** Encode and decode data with Base64 and hexadecimal. Securely erase sensitive data using random bytes.
- **Advanced Generation:** Tailor key and password generation with options for uppercase, dual cases, and more.
- **Password Strength Checker:** Evaluate password strength based on length, character types, and more.
- **Password Hashing:** Hash passwords using the SHA-256 algorithm with advanced salting.
- **Salt Generation:** Generate unique salts for enhanced password security.

## Installation

Install SwiftCrypt using `pip`:

```bash
pip install swiftcrypt
```
# Usage
Here's a quick example of generating a secure password using SwiftCrypt:

```python
from swiftcrypt import SecretGenerator

generator = SecretGenerator()
password = generator.generate_password(length=12, numbers=True, special_characters=True)
print("Generated Password:", password)
```
Check out our documentation for more detailed instructions and examples.

# Contribution
We welcome contributions! If you encounter issues or want to enhance SwiftCrypt, please submit a pull request or open an issue.

# License
SwiftCrypt is licensed under the MIT License.

Feel free to use SwiftCrypt in your projects and enjoy a safer development experience! If you have any questions or need assistance, please don't hesitate to reach out.

