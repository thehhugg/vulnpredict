"""Fixture: safe code that should NOT be flagged for eval/exec."""

import ast
import json


def safe_literal_eval(data):
    return ast.literal_eval(data)


def safe_json_parse(data):
    return json.loads(data)


def simple_math():
    return 2 + 2
