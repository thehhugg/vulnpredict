"""Fixture: class with methods and nested functions for edge case testing."""


class UserService:
    def get_user(self, user_id):
        return eval(user_id)

    def safe_method(self, name):
        return name.strip()


def outer_function(data):
    def inner_function(x):
        exec(x)

    inner_function(data)
