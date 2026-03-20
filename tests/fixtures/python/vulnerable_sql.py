"""Fixture: contains SQL injection patterns via taint analysis."""


def get_user(user_id):
    user_input = input("Enter user ID: ")
    import sqlite3
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = " + user_input)
    return cursor.fetchone()
