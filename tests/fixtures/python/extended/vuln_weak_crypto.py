"""Vulnerable weak cryptography patterns."""
import hashlib


def hash_password_md5(password):
    """Uses MD5 for password hashing — cryptographically broken."""
    return hashlib.md5(password.encode()).hexdigest()


def hash_token_sha1(token):
    """Uses SHA1 for token hashing — collision attacks possible."""
    return hashlib.sha1(token.encode()).hexdigest()
