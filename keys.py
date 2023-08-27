import random
import string
import hashlib
import uuid
import base64
import os

class Keys:
    def __init__(self):
        # Define lowercase alphabet characters
        self.alphabet = list(string.ascii_lowercase)
        self.alphabet_numbers = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"]
        self.alphabet_numbers.extend(self.alphabet)

    def generateKey(self, length=24, numbers=True, dashes=True, dash_range=6, uppercase=True):
        keyList = []
        iteration = -1

        for _ in range(length):
            iteration += 1

            # Insert dashes at specified intervals
            if dashes:
                if iteration == dash_range:
                    keyList.append("-")
                    iteration = 0

            alpha = self.alphabet
            if numbers:
                alpha = self.alphabet_numbers

            char = random.choice(alpha)
            keyList.append(char)

        key = "".join(keyList)

        if uppercase:
            key = key.upper()

        return key

    def KeyHash(self, data: bytes, algorithm="sha256"):
        h = hashlib.new(algorithm)
        h.update(data)
        hash_digest = h.hexdigest()
        return hash_digest

    def advancedKey(self, alpha: str, length: int, dashes: bool, dash_range: int, uppercase: bool, dual_cases: bool):
        keyList = []
        iteration = -1

        for _ in range(length):
            iteration += 1

            # Insert dashes at specified intervals
            if dashes:
                if iteration == dash_range:
                    keyList.append("-")
                    iteration = 0

            char = random.choice(alpha)

            if dual_cases:
                # Randomly alternate between uppercase and lowercase characters
                if random.choice([True, False]):
                    char = char.upper()
                else:
                    char = char.lower()

            keyList.append(char)

        key = "".join(keyList)

        # Convert key to uppercase if specified and not using dual cases
        if uppercase and not dual_cases:
            key = key.upper()

        return key

    def checkKey(self, key, keyLength: int, numbers: bool, amt_dashes: int or bool, uppercase: bool, dual_cases: bool):
        # Check key length and dash count if applicable
        if len(key) != keyLength:
            if isinstance(amt_dashes, bool):
                return 1
            else:
                keyLength += key.count("-")
                if keyLength != len(key):
                    return 1

        # Check dash count if specified
        if isinstance(amt_dashes, int):
            dash_amt = key.count("-")
            if amt_dashes != dash_amt:
                return 2

        # Check for lowercase characters when uppercase is required
        if uppercase and not dual_cases:
            if any(char.islower() for char in key):
                return 3

        # Check for both lowercase and uppercase characters when dual cases are required
        if dual_cases:
            has_lower = any(char.islower() for char in key)
            has_upper = any(char.isupper() for char in key)
            if not (has_lower and has_upper):
                return 4

        # Check for digits in the key if numbers are required
        if numbers:
            if not any(char.isdigit() for char in key):
                return 5

        # Key passed all checks
        return 0


    def generateUUID(self):
        generated_uuid = uuid.uuid4()
        return generated_uuid
    
    
class dataTransform:
    def __init__(self):
        pass
        
    def encodeBase64(self, data: bytes) -> str:
            encoded_data = base64.b64encode(data).decode("utf-8")
            return encoded_data

    def decodeBase64(self, encoded_data: str) -> bytes:
            decoded_data = base64.b64decode(encoded_data)
            return decoded_data

    def encodeHex(self, data: bytes) -> str:
            hex_data = data.hex()
            return hex_data

    def decodeHex(self, hex_data: str) -> bytes:
            decoded_data = bytes.fromhex(hex_data)
            return decoded_data
        
    def securelyEraseData(self, data: bytearray):
        random_bytes = os.urandom(len(data))

        for i in range(len(data)):
            data[i] = random_bytes[i]
            
            
class Passwords:
    def __init__(self):
        self.alphabet = list(string.ascii_lowercase)
        self.alphabet_numbers = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"]
        self.alphabet_numbers.extend(self.alphabet)