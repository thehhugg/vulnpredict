"""Fixture: contains hardcoded secrets and sensitive variable names."""


def connect_to_db(password="supersecret123"):
    api_key = "AKIAIOSFODNN7EXAMPLE"
    secret_token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
    db_credential = "root:password@localhost"
    return password, api_key, secret_token, db_credential


def process_auth(session_cookie, private_key):
    auth_token = "Bearer eyJhbGciOiJIUzI1NiJ9"
    return auth_token
