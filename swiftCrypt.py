import random
import string
import uuid
import base64
import secrets

class SecretGenerator:
    def __init__(self):
        self.alphabet_lowercase = list(string.ascii_lowercase)
        self.alphabet_numbers = list(string.digits)
        self.alphabet_special = list("!@#$%^&*")

    def generate_random_chars(self, alpha, length):
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
        encoded_data = base64.b64encode(data).decode("utf-8")
        return encoded_data

    def decode_base64(self, encoded_data: str) -> bytes:
        decoded_data = base64.b64decode(encoded_data)
        return decoded_data

    def encode_hex(self, data: bytes) -> str:
        hex_data = data.hex()
        return hex_data

    def decode_hex(self, hex_data: str) -> bytes:
        decoded_data = bytes.fromhex(hex_data)
        return decoded_data

    def securely_erase_data(self, data: bytearray):
        random_bytes = secrets.token_bytes(len(data))

        for i in range(len(data)):
            data[i] = random_bytes[i]



class AdvancedGenerator:
    def __init__(self):
        self.alphabet_lowercase = list(string.ascii_lowercase)
        self.alphabet_numbers = list(string.digits)
        self.alphabet_special = list("!@#$%^&*")

    def generate_random_chars(self, alpha, length):
        return [random.choice(alpha) for _ in range(length)]

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


