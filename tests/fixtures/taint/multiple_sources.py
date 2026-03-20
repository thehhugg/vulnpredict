# Multiple taint sources flowing to different sinks
user_input = input("Enter command: ")
form_data = request.form()
eval(user_input)
exec(form_data)
