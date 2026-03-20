# Multi-hop: taint flows through multiple function calls
def get_data():
    data = input("Enter: ")
    transform(data)

def transform(value):
    execute(value)

def execute(cmd):
    eval(cmd)
