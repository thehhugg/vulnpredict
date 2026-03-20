"""Fixture: safe code with no sensitive variable names."""

import os


def get_config():
    name = "application"
    port = 8080
    host = "localhost"
    return {"name": name, "port": port, "host": host}


def compute_total(items):
    return sum(item["price"] for item in items)
