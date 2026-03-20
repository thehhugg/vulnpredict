"""Vulnerable SSRF patterns."""
import requests
import urllib.request


def fetch_url(user_url):
    """Fetches a user-provided URL — SSRF risk."""
    return requests.get(user_url)


def fetch_with_urllib(user_url):
    """Opens a user-provided URL with urllib — SSRF risk."""
    return urllib.request.urlopen(user_url)
