# Interprocedural: taint flows from input() through process_data() to eval()
def get_user_input():
    data = input("Enter: ")
    process_data(data)

def process_data(value):
    eval(value)
