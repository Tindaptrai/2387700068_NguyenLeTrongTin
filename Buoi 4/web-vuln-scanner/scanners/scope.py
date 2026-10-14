from urllib.parse import urlparse
import ipaddress, os

def is_allowed_target(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        return False
    host = parsed.hostname.rstrip(".").lower()
    try:
        if ipaddress.ip_address(host).is_loopback:
            return True
    except ValueError:
        if host == "localhost" or host.endswith(".localhost"):
            return True
    allowed = {h.strip().lower() for h in os.getenv("LAB_ALLOWED_HOSTS", "").split(",") if h.strip()}
    return host in allowed
