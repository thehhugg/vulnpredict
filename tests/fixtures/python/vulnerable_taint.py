"""Fixture: contains taint flow from source to sink."""


def tainted_eval():
    user_data = input("Enter: ")
    eval(user_data)


def tainted_exec():
    code = input("Code: ")
    exec(code)
