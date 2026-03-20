"""Safe deserialization patterns."""
import json
import yaml


def load_json_data(text):
    """JSON parsing is safe — no code execution."""
    return json.loads(text)


def load_yaml_safe(text):
    """Uses yaml.load with SafeLoader — safe."""
    return yaml.load(text, Loader=yaml.SafeLoader)


def load_yaml_safe_alt(text):
    """Uses yaml.safe_load — safe."""
    return yaml.safe_load(text)
