"""Vulnerable LDAP injection patterns."""
import ldap


def search_user(conn, username):
    """Searches LDAP with unsanitized input — injection risk."""
    filter_str = f"(uid={username})"
    return conn.search_s("dc=example,dc=com", ldap.SCOPE_SUBTREE, filter_str)
