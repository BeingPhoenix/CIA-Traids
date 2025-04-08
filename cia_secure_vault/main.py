#!/usr/bin/env python3
import os
import sys
import argparse
import getpass
import shutil
from crypto_utils import encrypt_file, decrypt_file
from integrity import compute_hmac, verify_hmac
from backup import backup_file

# Global directories
VAULT_DIR = "vault"
BACKUP_DIR = "backup"
ASSETS_DIR = "assets"
BANNER_FILE = os.path.join(ASSETS_DIR, "banner.txt")

# ------------------------------
# UTILITY FUNCTIONS
# ------------------------------
def clear_screen():
    # Clear terminal screen depending on OS
    os.system('clear' if os.name == 'posix' else 'cls')

def print_banner():
    # Check if banner file exists and print it; otherwise print fallback banner.
    if os.path.isfile(BANNER_FILE):
        with open(BANNER_FILE, "r") as bf:
            banner = bf.read()
        print(banner)
    else:
        print("********** Phoenix[CIA S\\V] **********\n")

def ensure_directories():
    for directory in [VAULT_DIR, BACKUP_DIR, ASSETS_DIR]:
        if not os.path.isdir(directory):
            os.makedirs(directory)

def pause():
    input("\nPress Enter to return to the main menu...")

# ------------------------------
# FUNCTIONALITY MODULES (unchanged from previous code)
# ------------------------------
def add_file():
    """Encrypt a file and store it in the vault along with its HMAC and backup it."""
    input_path = input("Enter the full path of the file to encrypt: ").strip()
    if not os.path.isfile(input_path):
        print("Input file not found!")
        return
    filename = os.path.basename(input_path)
    encrypted_file = os.path.join(VAULT_DIR, filename + ".enc")
    hmac_file = encrypted_file + ".hmac"

    password = getpass.getpass("Enter encryption password: ")

    print("\n[Confidentiality] Encrypting file...")
    key = encrypt_file(input_path, encrypted_file, password)

    print("[Integrity] Computing HMAC for file integrity...")
    file_hmac = compute_hmac(encrypted_file, key)
    with open(hmac_file, "w") as f:
        f.write(file_hmac)

    print(f"\nFile encrypted and saved as:\n  {encrypted_file}")
    print(f"HMAC saved as:\n  {hmac_file}")

    # Backup functionality
    backup_file(encrypted_file, BACKUP_DIR)
    backup_file(hmac_file, BACKUP_DIR)
    print("[Availability] Backup completed.")

def retrieve_file():
    """Decrypt a file from the vault after verifying its integrity."""
    filename = input("Enter the base filename (without .enc) to decrypt: ").strip()
    encrypted_file = os.path.join(VAULT_DIR, filename + ".enc")
    hmac_file = encrypted_file + ".hmac"

    if not os.path.isfile(encrypted_file):
        print("Encrypted file not found in vault!")
        return
    if not os.path.isfile(hmac_file):
        print("HMAC file not found for the file!")
        return

    output_file = input("Enter output filename for the decrypted file: ").strip()
    password = getpass.getpass("Enter decryption password: ")

    temp_decrypted = "temp_decrypted.tmp"
    try:
        key = decrypt_file(encrypted_file, temp_decrypted, password)
    except Exception as e:
        print("Decryption failed:", e)
        return

    with open(hmac_file, "r") as f:
        stored_hmac = f.read().strip()
    if not verify_hmac(encrypted_file, stored_hmac, key):
        print("Integrity check failed! The file may have been tampered with.")
        os.remove(temp_decrypted)
        return
    else:
        print("Integrity check passed.")

    os.rename(temp_decrypted, output_file)
    print(f"File decrypted successfully and saved as:\n  {output_file}")

def verify_file():
    """Re-compute and verify the HMAC of an encrypted file."""
    filename = input("Enter the base filename (without .enc) to verify: ").strip()
    encrypted_file = os.path.join(VAULT_DIR, filename + ".enc")
    hmac_file = encrypted_file + ".hmac"

    if not os.path.isfile(encrypted_file) or not os.path.isfile(hmac_file):
        print("Required files not found in vault!")
        return

    password = getpass.getpass("Enter password to verify integrity: ")
    try:
        key = decrypt_file(encrypted_file, "temp_verify.tmp", password)
        os.remove("temp_verify.tmp")
    except Exception as e:
        print("Decryption failed:", e)
        return

    with open(hmac_file, "r") as f:
        stored_hmac = f.read().strip()
    if verify_hmac(encrypted_file, stored_hmac, key):
        print("Integrity verification successful. HMAC matches.")
    else:
        print("Integrity verification failed. HMAC does not match.")

def backup_command():
    """Backup an encrypted file from the vault to the backup directory."""
    filename = input("Enter the base filename (without .enc) to backup: ").strip()
    file_to_backup = os.path.join(VAULT_DIR, filename + ".enc")
    if not os.path.isfile(file_to_backup):
        print("Encrypted file not found in vault!")
        return
    backup_file(file_to_backup, BACKUP_DIR)
    print(f"File {file_to_backup} backed up to {BACKUP_DIR}")

# ------------------------------
# ADDITIONAL ADVANCED FEATURES
# ------------------------------
def list_vault_files():
    """List all encrypted files in the vault directory."""
    print("\nEncrypted Files in Vault:")
    files = [f for f in os.listdir(VAULT_DIR) if f.endswith(".enc")]
    if files:
        for idx, file in enumerate(files, 1):
            print(f" {idx}. {file}")
    else:
        print(" Vault is empty.")

def delete_file():
    """Delete an encrypted file (and its associated HMAC) from the vault."""
    filename = input("Enter the base filename (without .enc) to delete: ").strip()
    encrypted_file = os.path.join(VAULT_DIR, filename + ".enc")
    hmac_file = encrypted_file + ".hmac"
    confirmation = input(f"Are you sure you want to delete {filename}? (yes/no): ").strip().lower()
    if confirmation == "yes":
        for f in [encrypted_file, hmac_file]:
            if os.path.isfile(f):
                os.remove(f)
                print(f"Deleted {f}")
            else:
                print(f"{f} not found.")
    else:
        print("Deletion canceled.")

def show_cia_info():
    """Print some knowledge/information about the CIA Triad."""
    info = """
------------------ CIA Triad Overview ------------------
Confidentiality: Ensures that information is accessible only to those with authorized access.
  - In this project, data is protected using AES encryption.
  
Integrity: Maintains and assures the accuracy and completeness of data.
  - Here, file integrity is verified using HMAC-SHA256 to detect any tampering.
  
Availability: Ensures that information and resources are available to authorized users when needed.
  - Availability is enhanced by our backup functionality, ensuring files remain accessible.
---------------------------------------------------------
"""
    print(info)

# ------------------------------
# INTERACTIVE MAIN MENU SYSTEM
# ------------------------------
def interactive_menu():
    while True:
        clear_screen()
        print_banner()
        print("\n========== CIA Triad Secure File Vault Main Menu ==========")
        print("1. Add (Encrypt and store) a file")
        print("2. Retrieve (Decrypt) a file")
        print("3. Verify file integrity")
        print("4. Backup an encrypted file")
        print("5. List all files in the vault")
        print("6. Delete a file from the vault")
        print("7. Show CIA Triad Information")
        print("8. Exit")
        print("============================================================")
        choice = input("Enter your choice (1-8): ").strip()
        if choice == "1":
            add_file()
            pause()
        elif choice == "2":
            retrieve_file()
            pause()
        elif choice == "3":
            verify_file()
            pause()
        elif choice == "4":
            backup_command()
            pause()
        elif choice == "5":
            list_vault_files()
            pause()
        elif choice == "6":
            delete_file()
            pause()
        elif choice == "7":
            show_cia_info()
            pause()
        elif choice == "8":
            print("Exiting... Goodbye!")
            sys.exit(0)
        else:
            print("Invalid choice. Please enter a number between 1 and 8.")
            pause()

# ------------------------------
# MAIN ENTRY POINT
# ------------------------------
def main():
    ensure_directories()
    # If command-line arguments are provided, use argparse mode
    if len(sys.argv) > 1:
        parser = argparse.ArgumentParser(
            description="🔐 CIA Triad Secure File Vault - Encrypt, Verify, Decrypt, and Backup files securely",
            epilog="Example usage:\n"
                   "  python3 main.py add -i secret.txt\n"
                   "  python3 main.py retrieve -f secret.txt -o output.txt\n"
                   "  python3 main.py verify -f secret.txt\n"
                   "  python3 main.py backup -f secret.txt",
            formatter_class=argparse.RawTextHelpFormatter
        )
        subparsers = parser.add_subparsers(dest="command", help="Commands")

        # Add file command
        parser_add = subparsers.add_parser("add", help="Encrypt and add a file to the vault")
        parser_add.add_argument("-i", "--input", required=True, help="Path to input file")
        parser_add.set_defaults(func=lambda args: add_file())

        # Retrieve file command
        parser_retrieve = subparsers.add_parser("retrieve", help="Decrypt a file from the vault")
        parser_retrieve.add_argument("-f", "--filename", required=True, help="Base name of the file (without .enc)")
        parser_retrieve.add_argument("-o", "--output", required=True, help="Path to output decrypted file")
        parser_retrieve.set_defaults(func=lambda args: retrieve_file())

        # Verify integrity command
        parser_verify = subparsers.add_parser("verify", help="Verify the integrity of an encrypted file")
        parser_verify.add_argument("-f", "--filename", required=True, help="Base name of the file (without .enc)")
        parser_verify.set_defaults(func=lambda args: verify_file())

        # Backup command
        parser_backup = subparsers.add_parser("backup", help="Backup an encrypted file")
        parser_backup.add_argument("-f", "--filename", required=True, help="Base name of the file (without .enc)")
        parser_backup.set_defaults(func=lambda args: backup_command())

        args = parser.parse_args()
        if hasattr(args, "func"):
            args.func(args)
        else:
            parser.print_help()
    else:
        # No CLI arguments provided: launch interactive menu
        interactive_menu()

if __name__ == "__main__":
    main()
