# Tainted: input() flows directly to eval()
user_data = input("Enter: ")
eval(user_data)
