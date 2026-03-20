# Safe: function calls exist but no taint sources
def compute(x):
    return x * 2

def main():
    result = compute(42)
    print(result)
