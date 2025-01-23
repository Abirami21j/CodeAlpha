# Recommended Secure Login Code
def secure_login():
    print("=== Secure Login System ===")
    # Set secure credentials
    correct_username = "Abirami"
    correct_password = "Abirami"

    # Ask user for input
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    # Check credentials securely
    if username == correct_username and password == correct_password:
        print("Login successful!")
    else:
        print("Login failed! Invalid username or password.")

secure_login()