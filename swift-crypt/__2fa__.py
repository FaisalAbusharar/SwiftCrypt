from swiftcrypt import TwoFactorAuth

"""This line imports the TwoFactorAuth class from the swiftCrypt module. This class is responsible for handling two-factor authentication (2FA) operations."""

two_factor_auth = TwoFactorAuth()

"""Here, we create an instance of the TwoFactorAuth class, which allows us to use the methods and functionality defined within this class."""
# Registration process
user_secret_key = two_factor_auth.generate_secret_key()

"""This line generates a secret key using the generate_secret_key() method provided by the TwoFactorAuth class.
The secret key is a random string that is used to securely generate time-based one-time passwords (TOTPs) for the user."""

user_email = "voidycodes@gmail.com"

"""This line generates a QR code image using the generate_qr_code() method of the TwoFactorAuth class.
The method takes the user's secret key and email as parameters and generates a QR code that contains information for setting up 2FA."""

user_qr_code = two_factor_auth.generate_qr_code(user_secret_key, user_email)

"""Here, we use the send_qr_code_email() method to send the QR code image via email. The method takes the QR code image, user's email address,
sender's email address, and sender's email password as parameters to send the email containing the QR code."""

# Send the QR code via email
two_factor_auth.send_qr_code_email(user_qr_code, user_email,"tech.tweaks.contact@gmail.com","some_password_here")
print("QR code sent to email.")

two_factor_auth.generate_qr_code_and_print("user@example.com")

"""we use the generate_qr_code_and_print() method to generate the QR code image and print its base64-encoded version to the console. The method takes the user's email address as a parameter."""