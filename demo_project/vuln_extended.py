"""Extended vulnerability examples for VulnPredict demo project."""
import hashlib
import pickle
import xml.etree.ElementTree as ET

import requests
import yaml


# --- Deserialization ---
def load_user_session(cookie_data):
    """VULNERABLE: Deserializes user cookie with pickle."""
    return pickle.loads(cookie_data)


def load_config_safe(config_text):
    """SAFE: Uses yaml.safe_load."""
    return yaml.safe_load(config_text)


def load_config_unsafe(config_text):
    """VULNERABLE: Uses yaml.load without SafeLoader."""
    return yaml.load(config_text)


# --- SSRF ---
def fetch_webhook(url):
    """VULNERABLE: Fetches a user-controlled URL without validation."""
    return requests.get(url)


# --- Path Traversal ---
def serve_file(user_filename):
    """VULNERABLE: Opens a user-controlled filename."""
    return open(user_filename).read()


# --- XXE ---
def parse_upload(xml_data):
    """VULNERABLE: Parses XML without disabling external entities."""
    return ET.fromstring(xml_data)


# --- Weak Crypto ---
def hash_password(password):
    """VULNERABLE: Uses MD5 for password hashing."""
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_secure(password):
    """SAFE: Uses SHA-256 for password hashing."""
    return hashlib.sha256(password.encode()).hexdigest()
