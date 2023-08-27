import random
import string
import hashlib
import uuid
import base64
import os
import secrets

# SecretGenerator functionality
def test_secret_generator():
    key_length = 24
    key = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(key_length))
    print("Generated Key:", key)

    uuid_generated = str(uuid.uuid4())
    print("Generated UUID:", uuid_generated)

    password_length = 16
    password = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(password_length))
    print("Generated Password:", password)

# DataTransformer functionality
def test_data_transformer():
    data = b"hello"
    encoded_data = base64.b64encode(data).decode("utf-8")
    print("Encoded Base64:", encoded_data)

    decoded_data = base64.b64decode(encoded_data)
    print("Decoded Base64:", decoded_data.decode("utf-8"))

# AdvancedGenerator functionality
def test_advanced_generator():
    key_length = 16
    key = ''.join(random.choice("abc123") for _ in range(key_length))
    print("Advanced Key:", key)

    password_length = 20
    password = ''.join(random.choice("abcdef") for _ in range(password_length))
    print("Advanced Password:", password)

# Test all functionalities
def main():
    test_secret_generator()
    test_data_transformer()
    test_advanced_generator()

if __name__ == "__main__":
    main()
