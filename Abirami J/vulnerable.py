# Vulnerable Login Code
def vulnerable_login():
    print("=== Vulnerable Login System ===")
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    # Vulnerable logic: Always grants access regardless of input
    if username or password:
        print("Login successful! (This is insecure and allows anyone to log in)")
    else:
        print("Login failed!")

vulnerable_login()