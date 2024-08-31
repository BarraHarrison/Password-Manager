from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os

# Function to generate a Fernet key from the master password
def generate_key(master_pwd):
    salt = b'\x16\x12\xaf\x14\x89\xa7\x13\xcf'  # Fixed salt for consistent key derivation
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_pwd.encode()))
    return key

master_pwd = input("What is the master password? ")
key = generate_key(master_pwd)
fer = Fernet(key)

# Function to view stored passwords
def view():
    if not os.path.exists("passwords.txt"):
        print("No passwords saved yet.")
        return
    
    with open("passwords.txt", "r") as f:
        for line in f.readlines():
            data = line.rstrip()
            try:
                user, passw = data.split("||")
                decrypted_password = fer.decrypt(passw.encode()).decode()
                print(f"User: {user} | Password: {decrypted_password}")
            except Exception as e:
                print("There was an error decrypting the password:", e)

# Function to add new passwords
def add():
    name = input("Account Name: ")
    pwd = input("Password: ")
    encrypted_password = fer.encrypt(pwd.encode()).decode()
    with open("passwords.txt", "a") as f:
        f.write(name + "||" + encrypted_password + "\n")

# Main loop
while True:
    mode = input("Would you like to add a new password or view existing ones? (view/add). Press q if you want to quit: ").lower()
    if mode == "q":
        break
    elif mode == "view":
        view()
    elif mode == "add":
        add()
    else:
        print("Invalid mode.")
        continue
