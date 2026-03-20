"""Fixture: contains eval/exec calls that should be detected as dangerous."""

user_input = input("Enter expression: ")


def dangerous_eval(data):
    return eval(data)


def dangerous_exec(code):
    exec(code)


def dangerous_compile(source):
    compiled = compile(source, "<string>", "exec")
    exec(compiled)
