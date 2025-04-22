import hashlib
import requests

def check_password_breach(password: str) -> int:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=3)
        for line in response.text.splitlines():
            if line.startswith(suffix):
                return int(line.split(":")[1])
        return 0
    except:
        return -1  # API error