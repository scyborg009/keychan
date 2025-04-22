import argon2  # pip install argon2-cffi
import time

ph = argon2.PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4
)

def hash_password(password):
    return ph.hash(password)

def verify_password(hashed_pwd, input_pwd, max_attempts=3):
    for attempt in range(max_attempts):
        try:
            return ph.verify(hashed_pwd, input_pwd)
        except:
            if attempt == max_attempts - 1:
                return False
            time.sleep(5 * (attempt + 1))  # Anti-bruteforce delay