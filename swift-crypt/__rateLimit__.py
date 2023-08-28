from swiftCrypt import RateLimiter, returnIp


limiter = RateLimiter()
"""initiate the limiter"""

login_successful = False
"""wheather the login is correct or not"""

hostname, ip = returnIp()
"""returns the IP of the user aswell as the hostname."""
combined_key = f"{hostname}_{ip}"
"""Create a key, which is a mix of the hostname & ip"""

while True:
    if not limiter.check_rate_limit(hostname,ip,max_attempts=6,cooldown_duration=50):
            
#? The check_rate_limit function returns a bool.
#* if it returns True that means the user still has attempts left.
#! if it returns false that means the user has reached the limit.
#% IP is Optional, in this case we use it.
            
            print("Rate limit exceeded. Try again later.")
            break
    if login_successful:
        if combined_key in limiter.failed_attempts:
            #@ If the login is successful, we will reset the attempts.
            del limiter.failed_attempts[combined_key]  # Reset failed attempts if login successful
    else:
        """if the login is not successful, we will add subtract from
            attempts left"""
        limiter.record_failed_attempt(combined_key)
        print("attempted login")
        
"""
Expected output:
attempted login
attempted login
attempted login
attempted login
attempted login
attempted login
Rate limit exceeded. Try again later.

"""