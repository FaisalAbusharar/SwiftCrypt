from swiftCrypt import DigitalSignature

# Create an instance of the DigitalSignature class
digital_signature = DigitalSignature()

# Generate an RSA key pair
private_key, public_key = digital_signature.generate_key_pair()
private_key_second, public_key_second = digital_signature.generate_key_pair()

# Define the message to be signed
message = b"Hello, this is a message."

# Sign the message using the private key
signature = digital_signature.sign_message(private_key, message)

# Verify the signature using the public key and the original message
verification_result = digital_signature.verify_signature(public_key, message, signature)
verification_result_second = digital_signature.verify_signature(public_key_second, message, signature)

# Print the original message and the result of the signature verification
print("Message:", message.decode('utf-8'))
print("Signature Verified:", verification_result)
print("Bad Signature:", verification_result_second)


"""
Explaination:

in the first verification_result, it worked because the key that was used to sign the message is the same as the one we used.
however the second one was not, because the public key is different than the key used to sign the message.

"""