import swiftcrypt

random_generator = swiftcrypt.CGSR()

# Generate 16 bytes of cryptographically secure random data
random_data = random_generator.generate_cryptographically_secure_random(16)
print("Random Data:", random_data)