# Import necessary libraries
import os  # Used for interacting with the operating system
from cryptography.fernet import Fernet  # Used for encryption and decryption

# Function to generate a key for encryption
def generate_key():
    """
    Generates a key using the cryptography library's Fernet method.
    This key is used for encryption and decryption of passwords.
    The generated key must be kept secure and used consistently for encryption and decryption.
    """
    # Fernet.generate_key() generates a key that is used to encrypt and decrypt the data.
    key = Fernet.generate_key()

    # Save the key securely to a file (should be encrypted or stored securely in a real-world app)
    with open("secret.key", "wb") as key_file:
        key_file.write(key)  # Writing the key to a file so it can be reused

# Function to load the encryption key from the file
def load_key():
    """
    Loads the key for encryption from a file.
    If the key file does not exist, an error will be raised.
    """
    # Open the key file in binary read mode
    return open("secret.key", "rb").read()

# Function to encrypt a password
def encrypt_password(password):
    """
    Encrypts the password using the generated key.
    This ensures that the password is stored securely and not in plaintext.
    """
    key = load_key()  # Load the encryption key from the file
    fernet = Fernet(key)  # Create a Fernet instance using the loaded key

    # Encrypt the password
    encrypted_password = fernet.encrypt(password.encode())  # .encode() converts the password to bytes before encryption
    return encrypted_password

# Function to decrypt a password
def decrypt_password(encrypted_password):
    """
    Decrypts the encrypted password.
    This function takes an encrypted password and returns the original plaintext password.
    """
    key = load_key()  # Load the encryption key from the file
    fernet = Fernet(key)  # Create a Fernet instance using the loaded key

    # Decrypt the password and decode it back to a string
    decrypted_password = fernet.decrypt(encrypted_password).decode()  # .decode() converts the bytes back to a string
    return decrypted_password

# Function to save a password to a file (in an encrypted form)
def save_password(service, password):
    """
    Saves the encrypted password to a file. This allows retrieval of passwords later.
    Each service will have its own encrypted password stored.
    """
    encrypted_password = encrypt_password(password)  # Encrypt the password before saving
    with open("passwords.txt", "a") as file:  # Open the file in append mode
        # Save the service name (identifier) along with the encrypted password
        file.write(f"{service} | {encrypted_password.decode()}\n")

# Function to retrieve a password for a specific service
def retrieve_password(service):
    """
    Retrieves and decrypts the password for a given service.
    This function looks up the service in the password file and returns the original password.
    """
    with open("passwords.txt", "r") as file:  # Open the password file in read mode
        for line in file:
            # Split the line into service and encrypted password
            stored_service, encrypted_password = line.strip().split(" | ")

            # If the service matches, decrypt and return the password
            if stored_service == service:
                return decrypt_password(encrypted_password.encode())  # Return the decrypted password

    # If service is not found, return an error message
    return "Service not found."

# Main function to run the password manager
def main():
    """
    The main function allows the user to interact with the password manager.
    It provides options to add new passwords, retrieve existing passwords, or generate a new encryption key.
    """
    # Display the menu options to the user
    while True:
        print("\nPassword Manager:")
        print("1. Generate a new encryption key")
        print("2. Save a new password")
        print("3. Retrieve a password")
        print("4. Exit")

        # Get the user's choice
        choice = input("Choose an option: ")

        # Handle different user choices
        if choice == "1":
            generate_key()  # Call the function to generate the encryption key
            print("Encryption key generated and saved.")
        elif choice == "2":
            # Get the service name and password from the user
            service = input("Enter the service name (e.g., Gmail, Facebook): ")
            password = input("Enter the password: ")
            save_password(service, password)  # Save the encrypted password
            print(f"Password for {service} saved successfully.")
        elif choice == "3":
            # Get the service name to retrieve the password
            service = input("Enter the service name to retrieve the password: ")
            password = retrieve_password(service)  # Retrieve and decrypt the password
            print(f"Password for {service}: {password}")
        elif choice == "4":
            print("Exiting the password manager.")
            break  # Exit the loop and end the program
        else:
            print("Invalid option. Please try again.")

# Run the password manager if this script is executed directly
if __name__ == "__main__":
    main()
