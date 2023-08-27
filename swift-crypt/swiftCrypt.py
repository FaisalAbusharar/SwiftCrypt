import random
import string
import hashlib
import uuid
import base64
import secrets
import math

class SecretGenerator:
    def __init__(self):
        # Define character sets for generating secrets
        self.alphabet_lowercase = list(string.ascii_lowercase)
        self.alphabet_numbers = list(string.digits)
        self.alphabet_special = list("!@#$%^&*")

    def generate_random_chars(self, alpha, length):
        # Generate a list of random characters from the given character set
        return [random.choice(alpha) for _ in range(length)]

    def generate_key(self, length=24, numbers=True, dashes=True, dash_range=6, uppercase=True):
        alpha = self.alphabet_numbers + self.alphabet_lowercase

        if numbers:
            alpha.extend(self.alphabet_numbers)

        key_list = []
        iteration = -1

        for _ in range(length):
            iteration += 1

            if dashes and iteration == dash_range:
                key_list.append("-")
                iteration = 0

            char = random.choice(alpha)
            key_list.append(char)

        key = "".join(key_list)

        if uppercase:
            key = key.upper()

        return key

    def generate_uuid(self):
        # Generate a random UUID
        generated_uuid = uuid.uuid4()
        return generated_uuid

    def generate_password(self, length=16, numbers=True, uppercase=True, special_characters=True):
        alpha = self.alphabet_lowercase

        if numbers:
            alpha.extend(self.alphabet_numbers)
        if special_characters:
            alpha.extend(self.alphabet_special)

        password_list = self.generate_random_chars(alpha, length)

        if uppercase:
            password_list = [char.upper() if random.choice([True, False]) else char for char in password_list]

        return "".join(password_list)


class DataTransformer:
    def encode_base64(self, data: bytes) -> str:
        # Encode binary data into Base64
        encoded_data = base64.b64encode(data).decode("utf-8")
        return encoded_data

    def decode_base64(self, encoded_data: str) -> bytes:
        # Decode Base64 encoded data back to its original binary form
        decoded_data = base64.b64decode(encoded_data)
        return decoded_data

    def encode_hex(self, data: bytes) -> str:
        # Encode binary data into hexadecimal string
        hex_data = data.hex()
        return hex_data

    def decode_hex(self, hex_data: str) -> bytes:
        # Decode hexadecimal string back to its original binary form
        decoded_data = bytes.fromhex(hex_data)
        return decoded_data

    def securely_erase_data(self, data: bytearray):
        # Securely erase data by overwriting with random bytes
        random_bytes = secrets.token_bytes(len(data))

        for i in range(len(data)):
            data[i] = random_bytes[i]


class AdvancedGenerator:
    def __init__(self):
        # Define character sets for generating advanced secrets
        self.alphabet_lowercase = list(string.ascii_lowercase)
        self.alphabet_numbers = list(string.digits)
        self.alphabet_special = list("!@#$%^&*")

    def advanced_key(self, alpha: str, length: int, dashes: bool, dash_range: int, uppercase: bool, dual_cases: bool):
        key_list = []
        iteration = -1

        for _ in range(length):
            iteration += 1

            if dashes and iteration == dash_range:
                key_list.append("-")
                iteration = 0

            char = random.choice(alpha)

            if dual_cases:
                char = char.upper() if random.choice([True, False]) else char.lower()

            key_list.append(char)

        key = "".join(key_list)

        if uppercase and not dual_cases:
            key = key.upper()

        return key

    def advanced_password(self, alpha: str, length: int, uppercase: bool, dual_cases: bool):
        char_list = []

        for _ in range(length):
            char = random.choice(alpha)

            if dual_cases:
                char = char.upper() if random.choice([True, False]) else char.lower()

            char_list.append(char)

        password = "".join(char_list)

        if uppercase and not dual_cases:
            password = password.upper()

        return password


class Checker:
    def __init__(self):
      pass

    def check_password_strength(self, password,min_length=8,min_uppercase=1,min_lowercase=1,min_numbers=1,min_special=1,return_message=False):
        
        password_strength = 100
        
        
        if len(password) < min_length:
            password_strength -= 20
            if return_message != False: print(f"Password should be longer than {min_length-1}")
            

        uppercase_count = sum(1 for char in password if char.isupper())
        if uppercase_count < min_uppercase:
            password_strength -= 20
            if return_message != False: print("Password should contain at least {} uppercase letter(s).".format(min_uppercase))

        lowercase_count = sum(1 for char in password if char.islower())
        if lowercase_count < min_lowercase:
            password_strength -= 20
            if return_message != False: print("Password should contain at least {} lowercase letter(s).".format(min_lowercase))

        numbers_count = sum(1 for char in password if char.isdigit())
        if numbers_count < min_numbers:
            password_strength -= 20
            if return_message != False: print("Password should contain at least {} number(s)".format(min_numbers))

        special_count = sum(1 for char in password if char in "!@#$%^&*()-=+_)~")
        if special_count < min_special:
            password_strength -= 20
            if return_message != False: print("Password should contain at least {} special character(s).".format(min_special))
        
        if password_strength < 100:
            if return_message != False: return(f"Password Strength: {password_strength}%.")
        if return_message != False: return "Strong: Password meets the strength criteria."
        
        return password_strength
    
    def verify_password(self, password, hashed_password, salt):
        # Verify if a password matches a hashed password
        try_hashed_password = hashlib.sha256(password.encode('utf-8') + salt.encode('utf-8')).hexdigest()
        if try_hashed_password == hashed_password: return True
        else: return False

class Hash():
    def __init__(self):
        pass

    def hash_password(self, password, salt):
            # Hash a password using a combination of hashlib algorithms
            hashed_password = hashlib.sha256(password.encode('utf-8') + salt.encode('utf-8')).hexdigest()
            return hashed_password
                

class Salts:
    def __init__(self, characters=string.ascii_letters + string.digits):
        self.characters = characters

    def generate_salt(self, salt_length=None):
        if salt_length is None:
            salt_length = random.randint(10, 30)

        salt = ''.join(random.choice(self.characters) for _ in range(salt_length))
        return salt

    def generate_pool(self, pool_size: int, salt_length=None):
        salt_pool = [self.generate_salt(salt_length) for _ in range(pool_size)]
        return salt_pool

    def estimate_entropy(self, salt):
        # Estimate the entropy of the provided salt
        num_possible_characters = len(self.characters)
        entropy = math.log2(num_possible_characters) * len(salt)
        return entropy