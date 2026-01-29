import os
import json
import base64
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

VAULT_FILE = "vault.enc"
SALT = b"password-manager-salt"

def derive_key(master_password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def load_vault(fernet):
    if not os.path.exists(VAULT_FILE):
        return {}

    with open(VAULT_FILE, "rb") as f:
        encrypted_data = f.read()

    try:
        decrypted = fernet.decrypt(encrypted_data)
        return json.loads(decrypted.decode())
    except:
        print("❌ Wrong Master Password!")
        exit()

def save_vault(data, fernet):
    encrypted = fernet.encrypt(json.dumps(data).encode())
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)

def main():
    print("🔐 PASSWORD MANAGER")
    master_password = getpass.getpass("Enter Master Password: ")

    key = derive_key(master_password)
    fernet = Fernet(key)

    vault = load_vault(fernet)

    while True:
        print("\n1. Add Password")
        print("2. View Password")
        print("3. Delete Password")
        print("4. Exit")

        choice = input("Choose option: ")

        if choice == "1":
            site = input("Website: ")
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            vault[site] = {"username": username, "password": password}
            save_vault(vault, fernet)
            print("✅ Password saved!")

        elif choice == "2":
            site = input("Website: ")
            if site in vault:
                print("Username:", vault[site]["username"])
                print("Password:", vault[site]["password"])
            else:
                print("❌ Not found")

        elif choice == "3":
            site = input("Website: ")
            if site in vault:
                del vault[site]
                save_vault(vault, fernet)
                print("🗑️ Deleted")
            else:
                print("❌ Not found")

        elif choice == "4":
            break
        else:
            print("Invalid option")

if __name__ == "__main__":
    main()
