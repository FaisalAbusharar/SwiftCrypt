# SwiftCrypt

SwiftCrypt is a versatile Python module designed to facilitate secure secrets generation, transformation, and management in your applications. With a range of features including random key and password generation, data transformation, password strength assessment, hashing, and salt management, SwiftCrypt empowers developers with essential tools for enhancing security.

## Features

- **Secret Generation:** Generate random keys, UUIDs, and passwords using different character sets and options.
- **Advanced Options:** Leverage advanced generators for increased customization, supporting dual casing and advanced character sets.
- **Data Transformation:** Encode and decode data in Base64 and hexadecimal formats.
- **Password Strength Checking:** Evaluate password strength based on length, character types, and more.
- **Password Hashing:** Securely hash passwords using the SHA-256 algorithm and salt.
- **Salts:** Generate and manage salts to fortify password security.
- **Entropy Estimation:** Estimate entropy levels of provided salts.

## Installation

You can easily install SwiftCrypt using pip:

```bash
pip install swiftcrypt
```
# Usage
```python
# Import classes from the SwiftCrypt module
from swiftcrypt import SecretGenerator, DataTransformer, Checker, Hash, Salts

# Create instances of the classes
secret_gen = SecretGenerator()
data_transformer = DataTransformer()
checker = Checker()
hasher = Hash()
salts = Salts()

# Generate a random key
key = secret_gen.generate_key()

# Encode and decode data using Base64
data = b"Hello, world!"
encoded_data = data_transformer.encode_base64(data)
decoded_data = data_transformer.decode_base64(encoded_data)

# Check password strength
password = "SecurePassword123!"
strength = checker.check_password_strength(password)

# Hash a password with a salt
salt = salts.generate_salt()
hashed_password = hasher.hash_password(password, salt)

# Generate and estimate entropy of salts
generated_salt = salts.generate_salt()
entropy_estimate = salts.estimate_entropy(generated_salt)
```
# Examples
For more detailed usage examples and documentation, please refer to the examples directory and the documentation.

# Contributing
Contributions are highly appreciated! Feel free to open issues and submit pull requests for bug fixes, enhancements, and new features.

 #License
This project is licensed under the MIT License.


