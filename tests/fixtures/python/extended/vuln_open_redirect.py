"""Vulnerable open redirect patterns."""
from flask import redirect, request


def handle_redirect():
    """Redirects to user-controlled URL — open redirect risk."""
    next_url = request.args.get("next")
    return redirect(next_url)
