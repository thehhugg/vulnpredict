"""Vulnerable path traversal patterns."""
import os
import shutil


def read_user_file(filename):
    """Opens a user-controlled filename — path traversal risk."""
    return open(filename).read()


def join_user_path(user_path):
    """Joins a user-controlled path component — traversal risk."""
    base = "/var/data"
    full_path = os.path.join(base, user_path)
    return open(full_path).read()


def delete_user_file(user_path):
    """Removes a user-controlled path — traversal risk."""
    shutil.rmtree(user_path)
