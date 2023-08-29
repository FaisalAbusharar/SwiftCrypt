from swiftcrypt import SecureSessionManager
import time

# Create an instance of SecureSessionManager
session_manager = SecureSessionManager()

# Create a session for a user
user_id = "user123"
session_token = session_manager.create_session(user_id)
print("Session Token:", session_token)

# Validate the session
is_valid = session_manager.validate_session(session_token)
print("Is Valid Session:", is_valid)

# Wait for a while to simulate session expiration
time.sleep(5)

# Validate the session again
is_valid = session_manager.validate_session(session_token)
print("Is Valid Session After Expiration:", is_valid)

# End the session
session_manager.end_session(session_token)
is_valid = session_manager.validate_session(session_token)
print("Is Valid Session After Ending:", is_valid)
