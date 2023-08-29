import string
import hashlib
import uuid
import base64
import secrets
import math
import bcrypt
import qrcode
from cryptography.fernet import Fernet
import pyotp
import smtplib
import socket
import re
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import requests
from email.mime.multipart import MIMEMultipart
import keyring
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
import sqlite3
from io import BytesIO
import time




class SecretGenerator:
    def __init__(self):
        # Define character sets for generating secrets
        self.alphabet_lowercase = list(string.ascii_lowercase)
        self.alphabet_numbers = list(string.digits)
        self.alphabet_special = list("!@#$%^&*")

    def generate_random_chars(self, alpha, length):
        """
        Generate a list of random characters from the given character set.

        Args:
            alpha (list): List of characters to choose from.
            length (int): Number of characters to generate.

        Returns:
            list: List of randomly generated characters.
        """
        # Generate a list of random characters from the given character set
        return [secrets.choice(alpha) for _ in range(length)]

    def generate_key(self, length=24, numbers=True, dashes=True, dash_range=6, uppercase=True):
        """
        Generate a secret key with customizable options.

        Args:
            length (int, optional): Length of the generated key. Default is 24.
            numbers (bool, optional): Include numbers in the key. Default is True.
            dashes (bool, optional): Include dashes in the key. Default is True.
            dash_range (int, optional): Interval for adding dashes. Default is 6.
            uppercase (bool, optional): Convert key to uppercase. Default is True.

        Returns:
            str: Generated secret key.
        """
        
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

            char = secrets.choice(alpha)
            key_list.append(char)

        key = "".join(key_list)

        if uppercase:
            key = key.upper()

        return key

    def generate_uuid(self):
        """
        Generate a random UUID.

        Returns:
            UUID: Generated UUID.
        """
        # Generate a random UUID
        generated_uuid = uuid.uuid4()
        return generated_uuid

    def generate_password(self, length=16, numbers=True, uppercase=True, special_characters=True):
        """
        Generate a random password.

        Args:
            length (int, optional): Length of the password. Default is 16.
            numbers (bool, optional): Include numbers in the password. Default is True.
            uppercase (bool, optional): Include uppercase letters in the password. Default is True.
            special_characters (bool, optional): Include special characters in the password. Default is True.

        Returns:
            str: Generated password.
        """
       
        alpha = self.alphabet_lowercase

        if numbers:
            alpha.extend(self.alphabet_numbers)
        if special_characters:
            alpha.extend(self.alphabet_special)

        password_list = self.generate_random_chars(alpha, length)

        if uppercase:
            password_list = [char.upper() if secrets.choice([True, False]) else char for char in password_list]

        return "".join(password_list)


class DataTransformer:
    def encode_base64(self, data: bytes) -> str:
        """
        Encode binary data into Base64.

        Args:
            data (bytes): Binary data to be encoded.

        Returns:
            str: Base64 encoded data.
        """
        # Encode binary data into Base64
        encoded_data = base64.b64encode(data).decode("utf-8")
        return encoded_data

    def decode_base64(self, encoded_data: str) -> bytes:
        """
        Decode Base64 encoded data back to its original binary form.

        Args:
            encoded_data (str): Base64 encoded data.

        Returns:
            bytes: Decoded binary data.
        """
        # Decode Base64 encoded data back to its original binary form
        decoded_data = base64.b64decode(encoded_data)
        return decoded_data

    def encode_hex(self, data: bytes) -> str:
        """
        Encode binary data into hexadecimal string.

        Args:
            data (bytes): Binary data to be encoded.

        Returns:
            str: Hexadecimal encoded data.
        """

        # Encode binary data into hexadecimal string
        hex_data = data.hex()
        return hex_data

    def decode_hex(self, hex_data: str) -> bytes:
        """
        Decode hexadecimal string back to its original binary form.

        Args:
            hex_data (str): Hexadecimal encoded data.

        Returns:
            bytes: Decoded binary data.
        """
        # Decode hexadecimal string back to its original binary form
        decoded_data = bytes.fromhex(hex_data)
        return decoded_data

    def securely_erase_data(self, data: bytearray):
        """
        Securely erase data by overwriting with random bytes.

        Args:
            data (bytearray): Data to be securely erased.
        """

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
        """
        Generate an advanced secret key with customizable options.

        Args:
            alpha (str): Character set to choose from.
            length (int): Length of the generated key.
            dashes (bool): Include dashes in the key.
            dash_range (int): Interval for adding dashes.
            uppercase (bool): Convert key to uppercase.
            dual_cases (bool): Use both upper and lower cases.

        Returns:
            str: Generated advanced secret key.
        """
        
        key_list = []
        iteration = -1

        for _ in range(length):
            iteration += 1

            if dashes and iteration == dash_range:
                key_list.append("-")
                iteration = 0

            char = secrets.choice(alpha)

            if dual_cases:
                char = char.upper() if secrets.choice([True, False]) else char.lower()

            key_list.append(char)

        key = "".join(key_list)

        if uppercase and not dual_cases:
            key = key.upper()

        return key

    def advanced_password(self, alpha: str, length: int, uppercase: bool, dual_cases: bool):
        char_list = []
        """
        Generate an advanced password with customizable options.

        Args:
            alpha (str): Character set to choose from.
            length (int): Length of the generated password.
            uppercase (bool): Convert password to uppercase.
            dual_cases (bool): Use both upper and lower cases.

        Returns:
            str: Generated advanced password.
        """
        
        for _ in range(length):
            char = secrets.choice(alpha)

            if dual_cases:
                char = char.upper() if secrets.choice([True, False]) else char.lower()

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
        
        """
        Check the strength of a password based on specified criteria.

        Args:
            password (str): The password to be checked.
            min_length (int, optional): Minimum required length. Default is 8.
            min_uppercase (int, optional): Minimum required uppercase letters. Default is 1.
            min_lowercase (int, optional): Minimum required lowercase letters. Default is 1.
            min_numbers (int, optional): Minimum required numbers. Default is 1.
            min_special (int, optional): Minimum required special characters. Default is 1.
            return_message (bool, optional): Return a message indicating the result. Default is False.

        Returns:
            int/str: Password strength percentage or a message.
        """

        
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
    
    def verify_password(self, password, hashed_password, salt, algorithm='sha256'):
        # Verify if a password matches a hashed password using the specified algorithm
        """
        Verify if a password matches a hashed password using the specified algorithm.

        Args:
            password (str): Password to be verified.
            hashed_password (str): Hashed password to compare against.
            salt (str): Salt used during hashing.
            algorithm (str, optional): Hashing algorithm. Default is 'sha256'.

        Returns:
            bool: True if password matches, False otherwise.
        """
        if algorithm.lower() not in hashlib.algorithms_available:
            raise ValueError("Unsupported algorithm")

        # Create a hashlib object for the chosen algorithm
        hasher = hashlib.new(algorithm.lower())

        # Hash the entered password with the same salt
        password_salt_bytes = (password + salt).encode('utf-8')
        hasher.update(password_salt_bytes)
        try_hashed_password = hasher.hexdigest()

        return try_hashed_password == hashed_password

class Hash():
    def __init__(self):
        pass

    def hash_password(self, password, salt, algorithm="sha256"):
            """
            Hash a password using a combination of hashlib algorithms.

            Args:
                password (str): Password to be hashed.
                salt (str): Salt to be combined with the password.
                algorithm (str, optional): Hashing algorithm. Default is "sha256".

            Returns:
                str: Hashed password.
            """
        
            # Hash a password using a combination of hashlib algorithms
            
            if algorithm.lower() not in hashlib.algorithms_available:
                raise ValueError("Unsupported algorithm")

        # Create a hashlib object for the chosen algorithm
            hasher = hashlib.new(algorithm.lower())

        # Hash the password and salt
            password_salt_bytes = (password + salt).encode('utf-8')
            hasher.update(password_salt_bytes)
            hashed_password = hasher.hexdigest()
            
            return hashed_password
                

class Salts:
    def __init__(self, characters=string.ascii_letters + string.digits):
        self.characters = characters

    def generate_salt(self, salt_length=None):
        """
        Generate a random salt.

        Args:
            salt_length (int, optional): Length of the salt. Default is None.

        Returns:
            str: Generated salt.
        """
        if salt_length is None:
            salt_length = secrets.randint(10, 30)

        salt = ''.join(secrets.choice(self.characters) for _ in range(salt_length))
        return salt

    def generate_pool(self, pool_size: int, salt_length=None):
        """
        Generate a pool of random salts.

        Args:
            pool_size (int): Number of salts to generate.
            salt_length (int, optional): Length of the salts. Default is None.

        Returns:
            list: List of generated salts.
        """
        salt_pool = [self.generate_salt(salt_length) for _ in range(pool_size)]
        return salt_pool

    def estimate_entropy(self, salt):
        """
        Estimate the entropy of a provided salt.

        Args:
            salt (str): Salt for entropy estimation.

        Returns:
            float: Estimated entropy value.
        """
        # Estimate the entropy of the provided salt
        num_possible_characters = len(self.characters)
        entropy = math.log2(num_possible_characters) * len(salt)
        return entropy
    
    
    


class AdvancedFileTransform:
    def __init__(self):
        pass

    def generate_key(self, password):
        """
        Generate a cryptographic key from a password.

        Args:
            password (str): Password to generate the key.

        Returns:
            bytes: Generated key.
        """
        # Generate a salt for bcrypt
        salt = bcrypt.gensalt()

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        return hashed_password

    def encrypt_file(self, input_file, output_file, password):
        """
        Generate a cryptographic key from a password.

        Args:
            password (str): Password to generate the key.

        Returns:
            bytes: Generated key.
        """
        
        key = self.generate_key(password)
        fernet_key = Fernet.generate_key()
        fernet = Fernet(fernet_key)

        with open(input_file, 'rb') as f:
            plaintext = f.read()

        ciphertext = fernet.encrypt(plaintext)

        with open(output_file, 'wb') as f:
            f.write(key)
            f.write(fernet_key)
            f.write(ciphertext)

    def decrypt_file(self, input_file, output_file, password):
        
        """
        Decrypt an encrypted file using a password-derived key.

        Args:
            input_file (str): Path to the input encrypted file.
            output_file (str): Path to the output decrypted file.
            password (str): Password to generate the decryption key.
        """
        
        with open(input_file, 'rb') as f:
            key = f.read(60)  # bcrypt hash
            fernet_key = f.read(32)  # Fernet key
            ciphertext = f.read()

        if bcrypt.checkpw(password.encode('utf-8'), key):
            fernet = Fernet(fernet_key)
            plaintext = fernet.decrypt(ciphertext)

            with open(output_file, 'wb') as f:
                f.write(plaintext)
        else:
            raise ValueError("Incorrect password")



class TwoFactorAuth:
    def generate_secret_key(self):
        # Generate a secret key for the user
        
        return pyotp.random_base32()

    def generate_qr_code(self, secret_key, username):
        # Generate a URL for the QR code
        totp = pyotp.TOTP(secret_key, interval=30)
        url = totp.provisioning_uri(username, issuer_name="SwiftCrypt")

        # Return the URL to generate a QR code
        return url

    def verify_2fa_code(self, secret_key, code):
        """
        Verify a two-factor authentication code against a secret key.

        Args:
            secret_key (str): Secret key associated with the user.
            code (str): Two-factor authentication code to verify.

        Returns:
            bool: True if the code is valid, False otherwise.
        """
        # Verify the TOTP code
        totp = pyotp.TOTP(secret_key, interval=30)
        return totp.verify(code)
    
    
    def generate_qr_code(self, secret_key, username,issuer_name="SwiftCrypt"):
        # Generate a URL for the QR code
        """
        Generate a QR code for two-factor authentication.

        Args:
            secret_key (str): Secret key generated for the user.
            username (str): User's username or identifier.
            issuer_name (str, optional): Name of the issuer. Default is "SwiftCrypt".

        Returns:
            PIL.Image.Image: QR code image.
        """
        
        totp = pyotp.TOTP(secret_key, interval=30)
        url = totp.provisioning_uri(username, issuer_name=issuer_name)

        # Generate a QR code image
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(url)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white")

        # Create an in-memory buffer to store the image
        img_buffer = BytesIO()
        qr_img.save(img_buffer, format="PNG")
        img_buffer.seek(0)

        # Return the image buffer
        return img_buffer

    def send_qr_code_email(self, qr_img, user_email,server_email,server_login):
        # Send the QR code image via email
        
        """
        Generate a secret key for two-factor authentication.

        Returns:
            str: Generated secret key.
        """
       
        to_email = user_email

        msg = MIMEMultipart()
        msg['From'] = server_email
        msg['To'] = to_email
        msg['Subject'] = "Your 2FA QR Code"

        msg.attach(MIMEImage(qr_img.getvalue(), name="qrcode.png"))

        # Setup the SMTP server and send the email
        smtp_server = smtplib.SMTP('smtp.gmail.com', 587)
        smtp_server.starttls()
        smtp_server.login(server_email, server_login)
        smtp_server.sendmail(server_email, to_email, msg.as_string())
        smtp_server.quit()


    def generate_qr_code_and_print(self, user_email):
        
        """
        Generate a QR code for two-factor authentication and print it.

        Args:
            user_email (str): User's email address for identification.
        """
        
        user_secret_key = self.generate_secret_key()
        user_qr_code = self.generate_qr_code(user_secret_key, user_email)
        
        # Convert the image buffer to a base64-encoded string
        base64_qr_code = base64.b64encode(user_qr_code.getvalue()).decode('utf-8')
        
        # Print the base64-encoded image
        print(base64_qr_code)


class RateLimiter:
    def __init__(self):
        self.failed_attempts = {}  # Store failed login attempts with timestamps

    def check_rate_limit(self, user_id, ip_address=None, max_attempts=5,
                         cooldown_duration=60):
        
        """
        Check if a user's login attempts are within rate limits.

        Args:
            user_id (str): User identifier.
            ip_address (str, optional): User's IP address. Default is None.
            max_attempts (int, optional): Maximum allowed login attempts. Default is 5.
            cooldown_duration (int, optional): Cooldown time in seconds. Default is 60.

        Returns:
            bool: True if within rate limits, False otherwise.
        """

        
        if ip_address == None:
            combined_key = {user_id}
        else:
            combined_key = f"{user_id}_{ip_address}"

        if combined_key in self.failed_attempts:
            attempts, last_attempt_time = self.failed_attempts[combined_key]
            if attempts >= max_attempts and time.time() - last_attempt_time < cooldown_duration:
                return False  # Rate limit exceeded
        return True

    def record_failed_attempt(self, combined_key):
      
        """
        Record a failed login attempt for rate limiting.

        Args:
            combined_key (str): Combined identifier (user_id + ip_address).
        """


        if combined_key in self.failed_attempts:
            attempts, _ = self.failed_attempts[combined_key]
            self.failed_attempts[combined_key] = (attempts + 1, time.time())
        else:
            self.failed_attempts[combined_key] = (1, time.time())


def returnIp(mode=None):
    url = 'https://api.ipify.org'
    response = requests.get(url)
    ip_address = response.text
    hostname = socket.gethostname()
    if mode == None:
        return hostname, ip_address
    elif mode == "ip":
        return ip_address
    
    
class DataMasking:
    def __init__(self):
        pass
    
    def mask_data(self, text, masking_character="*", chars_to_mask=4):
        
        """
        Mask sensitive data with a masking character.

        Args:
            text (str): Text containing sensitive data.
            masking_character (str, optional): Character used for masking. Default is "*".
            chars_to_mask (int, optional): Number of characters to mask. Default is 4.

        Returns:
            str: Masked text.
        """
        
        masked_text = re.sub(r'[a-zA-Z0-9]{%d}' % chars_to_mask, masking_character * chars_to_mask, text)
        return masked_text
            
    def credit_card_mask(self,text,masking_character="*"):
        
        """
        Mask a credit card number, revealing only the last four digits.

        Args:
            text (str): Credit card number.
            masking_character (str, optional): Character used for masking. Default is "*".

        Returns:
            str: Masked credit card number.
        """
        
        try:
            int(text)
        except:
            raise ValueError("credit_card_mask function only takes numbers.")
        
        return( (len(text) - 3) * masking_character + text[-3:])
        
        
class DigitalSignature:
    def __init__(self):
        pass
    
    def generate_key_pair(self):
        
        """
        Generate a key pair for digital signatures.

        Returns:
            tuple: Private key and public key.
        """
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def sign_message(self, private_key, message):
        
        """
        Sign a message using a private key.

        Args:
            private_key (str): Private key for signing.
            message (str): Message to be signed.

        Returns:
            str: Digital signature.
        """
        
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    def verify_signature(self, public_key, message, signature):
        
        """
        Verify a digital signature using a public key.

        Args:
            public_key (str): Public key for verification.
            message (str): Message to be verified.
            signature (str): Digital signature to be verified.

        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        
        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False
        
# for some reason pypi wont recognize the new changes.
class SecureInputHandler:
    """
    A class for securely interacting with SQLite databases.
    """
    def __init__(self, db_path):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor() 
       

    def execute_secure_query(self, query, params=None):
        
        """
        Execute a secure database query with parameterized inputs.

        Args:
            query (str): SQL query with placeholders for parameters.
            params (tuple, optional): Parameters to be substituted into the query.

        Returns:
            list: List of query results.
        """
        
        try:
            if params:
                self.cursor.execute(query, params)
            else:
                self.cursor.execute(query)
            
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            print("Error executing query:", e)
            self.conn.rollback()
            return False
        
   
        
    def create_table(self, table="users"):
        """
        Create a table in the database.

        Args:
            table (str, optional): Name of the table to create. Default is "users".
        """
        
        print("Creating table:", table)
        create_table_query = f"""
        CREATE TABLE IF NOT EXISTS {table} (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
        """
        try:
            self.cursor.execute(create_table_query)
            self.conn.commit()
            print("Table created successfully.")
        except sqlite3.Error as e:
            print("Error creating table:", e)
            self.conn.rollback()
            
    def get_user_info(self, username, table="users"):
        
        """
        Retrieve user information from the database.

        Args:
            username (str): Username to query.
            table (str, optional): Table name to query. Default is "users".

        Returns:
            tuple: User information retrieved from the database.
        """


        query = f"SELECT * FROM {table} WHERE username = ?"
        params = (username,)
        
        self.cursor.execute(query, params)
        user_info = self.cursor.fetchone()  # Retrieve the first matching row
        
        return user_info


    def close_connection(self):
        self.conn.close()
        """
        Close the database connection.
        """


class CGSR:
    def __init__(self):
        pass
    
    def generate_cryptographically_secure_random(self, num_bytes):
        """
        Generate cryptographically secure random bytes.

        Args:
            num_bytes (int): The number of random bytes to generate.

        Returns:
            bytes: A bytes object containing cryptographically secure random data.
        """
        return secrets.token_bytes(num_bytes)
    
    

class SecureSecretStorage:
    def __init__(self, service_name):
        self.service_name = service_name

    def store_secret(self, username, password):
        """
        Store a secret securely.

        Args:
            username (str): The username associated with the secret.
            password (str): The secret password to store.
        """
        keyring.set_password(self.service_name, username, password)

    def retrieve_secret(self, username):
        """
        Retrieve a secret securely.

        Args:
            username (str): The username associated with the secret.

        Returns:
            str: The retrieved secret password.
        """
        return keyring.get_password(self.service_name, username)

    def delete_secret(self, username):
        """
        Delete a stored secret.

        Args:
            username (str): The username associated with the secret.
        """
        keyring.delete_password(self.service_name, username)
        
        
class SecureSessionManager:
    def __init__(self):
        self.sessions = {}

    def create_session(self, user_id):
        """
        Create a new session for the user.

        Args:
            user_id (str): The user's unique identifier.

        Returns:
            str: The generated session token.
        """
        session_token = str(uuid.uuid4())
        self.sessions[session_token] = {
            'user_id': user_id,
            'timestamp': time.time()
        }
        return session_token

    def validate_session(self, session_token, max_session_age=3600):
        """
        Validate a session token.

        Args:
            session_token (str): The session token to validate.
            max_session_age (int): Maximum session age in seconds.

        Returns:
            bool: True if the session is valid, False otherwise.
        """
        if session_token in self.sessions:
            session = self.sessions[session_token]
            current_time = time.time()
            session_age = current_time - session['timestamp']
            if session_age <= max_session_age:
                # Refresh the session timestamp
                session['timestamp'] = current_time
                return True
            else:
                # Session has expired
                del self.sessions[session_token]
        return False

    def end_session(self, session_token):
        """
        End a session and remove it from the session storage.

        Args:
            session_token (str): The session token to end.
        """
        if session_token in self.sessions:
            del self.sessions[session_token]

class SecureFileHandler:
    def __init__(self, encryption_key):
        """
        Initialize the SecureFileHandler with an encryption key.

        Args:
            encryption_key (bytes): Encryption key used for Fernet encryption.
        """
        self.encryption_key = encryption_key
        self.fernet = Fernet(self.encryption_key)

    def encrypt_and_upload_file(self, input_file, output_file):
        """
        Encrypt a file using Fernet encryption and upload it.

        Args:
            input_file (str): Path to the input file to be encrypted.
            output_file (str): Path to the output encrypted file.

        Returns:
            str: Hash value of the plaintext for integrity verification.
        """
        # Read the plaintext from the input file
        with open(input_file, 'rb') as f:
            plaintext = f.read()

        # Encrypt the plaintext using Fernet
        ciphertext = self.fernet.encrypt(plaintext)

        # Calculate a hash of the plaintext for integrity verification
        hash_value = hashlib.sha256(plaintext).hexdigest()

        # Write the encrypted ciphertext to the output file
        with open(output_file, 'wb') as f:
            f.write(ciphertext)

        return hash_value

    def download_and_decrypt_file(self, input_file, output_file, expected_hash):
        """
        Download an encrypted file, decrypt it, and verify integrity.

        Args:
            input_file (str): Path to the input encrypted file.
            output_file (str): Path to the output decrypted file.
            expected_hash (str): Hash value of the original plaintext for integrity verification.

        Raises:
            ValueError: If integrity check fails.

        Returns:
            None
        """
        # Read the encrypted ciphertext from the input file
        with open(input_file, 'rb') as f:
            ciphertext = f.read()

        # Decrypt the ciphertext using Fernet
        plaintext = self.fernet.decrypt(ciphertext)

        # Calculate a hash of the decrypted plaintext for integrity verification
        calculated_hash = hashlib.sha256(plaintext).hexdigest()

        # Compare calculated hash with expected hash
        if calculated_hash != expected_hash:
            raise ValueError("Integrity check failed. The file might be tampered.")

        # Write the decrypted plaintext to the output file
        with open(output_file, 'wb') as f:
            f.write(plaintext)

