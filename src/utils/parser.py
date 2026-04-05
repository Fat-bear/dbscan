import re
from urllib.parse import urlparse

def parse_db_url(url):
    """
    Parse database URL and return connection details.
    Supports formats like: redis://host:port, mysql://user:pass@host:port/db, etc.
    """
    parsed = urlparse(url)
    db_type = parsed.scheme.lower()

    if db_type not in ['redis', 'mysql', 'postgresql', 'mongodb']:
        raise ValueError(f"Unsupported database type: {db_type}")

    host = parsed.hostname
    port = parsed.port
    username = parsed.username
    password = parsed.password
    database = parsed.path.lstrip('/') if parsed.path else None

    return {
        'type': db_type,
        'host': host,
        'port': port,
        'username': username,
        'password': password,
        'database': database
    }