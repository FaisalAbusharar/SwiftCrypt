from swiftcrypt import SecureSecretStorage

# Create an instance of SecureSecretStorage
secret_storage = SecureSecretStorage(service_name="my_app")

# Store a secret
secret_storage.store_secret(username="user123", password="secretpassword")

# Retrieve a secret
retrieved_password = secret_storage.retrieve_secret(username="user123")
print("Retrieved Password:", retrieved_password)

# Delete a stored secret
secret_storage.delete_secret(username="user123")