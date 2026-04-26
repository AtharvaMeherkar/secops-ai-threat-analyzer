import urllib.parse
import re

class InputValidationError(Exception):
    pass

def validate_url(url: str) -> bool:
    """
    Validates that the provided URL is well-formed.
    Raises InputValidationError if invalid.
    """
    if not url:
        raise InputValidationError("URL cannot be empty.")
    
    # Basic URL regex to ensure it looks like a valid http/https URL
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
        r'localhost|' # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    if re.match(regex, url):
        return True
    
    raise InputValidationError(f"Invalid URL format. Must start with http:// or https://")

def sanitize_url(url: str) -> str:
    """
    Strips lingering trailing slashes and spaces.
    """
    url = url.strip()
    if url.endswith('/'):
        url = url[:-1]
    return url
