# Tainted input is sanitized before reaching sink
# The taint tracker should still flag this because it doesn't track sanitization
# (documenting current behavior — sanitization awareness is a future enhancement)
user_data = input("Enter: ")
safe_data = int(user_data)
eval(safe_data)
