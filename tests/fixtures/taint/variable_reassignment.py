# Variable reassignment: tainted var reassigned to safe value
user_data = input("Enter: ")
user_data = "safe_hardcoded_value"
eval(user_data)
