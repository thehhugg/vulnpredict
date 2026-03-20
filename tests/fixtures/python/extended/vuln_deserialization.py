"""Vulnerable deserialization patterns."""
import pickle
import yaml
import marshal


def load_user_data(data):
    """Deserializes user-provided data with pickle — RCE risk."""
    return pickle.loads(data)


def load_yaml_unsafe(text):
    """Uses yaml.load without SafeLoader — code execution risk."""
    return yaml.load(text)


def load_marshal_data(raw):
    """Deserializes with marshal — untrusted data risk."""
    return marshal.loads(raw)
