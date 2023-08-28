from swiftCrypt import RateLimiter


limiter = RateLimiter()
"""initiate the limiter"""

login_successful = False
"""wheather the login is correct or not"""

user_id = "user123"
"""the user_id is how we check how many attempts have been made."""

while True:
    if not limiter.check_rate_limit(user_id,6):
            
#? The check_rate_limit function returns a bool.
#* if it returns True that means the user still has attempts left.
#! if it returns false that means the user has reached the limit.
            
            print("Rate limit exceeded. Try again later.")
            break
    if login_successful:
        if user_id in limiter.failed_attempts:
            #@ If the login is successful, we will reset the attempts.
            del limiter.failed_attempts[user_id]  # Reset failed attempts if login successful
    else:
        """if the login is not successful, we will add subtract from
            attempts left"""
        limiter.record_failed_attempt(user_id)
        print("attempted login")
        
