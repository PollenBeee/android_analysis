from urllib.parse import urlparse
import re

def is_url_safe(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    query = parsed.query.lower()

    # Heuristic flags
    if url.startswith("http://"):
        return True, "Uses insecure HTTP"
    
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain) or re.search(r'http://\d', url):
        return True, "Uses IP address instead of domain"

    if len(domain.split(".")) > 4:
        return True, f"Too many subdomains: {domain}"

    if any(x in query for x in ["token=", "auth=", "session=", "access_key", "key="]):
        return True, "Sensitive data in query string"

    return False, "Safe"
