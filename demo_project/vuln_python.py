# Example vulnerable Python code for VulnPredict demo

# 1. Use of eval with user input (code injection)
user_code = input('Enter code: ')
eval(user_code)

# 2. Unsanitized SQL query (SQL injection)
def get_user(cursor, username):
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)

# 3. Hardcoded password (sensitive data)
PASSWORD = 'supersecret123'

def login(user, pw):
    if pw == PASSWORD:
        print('Logged in!')

# 4. Outdated dependency usage (simulate by importing a known old package)
import xmlrpc.client  # Known for past vulnerabilities 