import secrets
import hashlib
import os
import string

# --- Configuration ---
KEY_DERIVATION_ITERATIONS = 100000  # Number of iterations for PBKDF2
KEY_LENGTH = 32                   # Length of the derived key in bytes (e.g., for AES-256)
PASSWORD_LENGTH = 16              # Default length for generated passwords

# --- In-memory "Vault" (for demonstration purposes only) ---
# In a real application, this would be securely encrypted and persisted.
# Note: 'password_placeholder' here stores the plain password for simplicity,
# but in a real app, it would be actual ciphertext encrypted with master_encryption_key.
vault = {}
master_key_salt = None
master_encryption_key = None

def generate_salt(length=16):
    """Generates a random salt."""
    return os.urandom(length)

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a cryptographic key from a password and salt using PBKDF2.
    This is a crucial step for securing a master password.
    """
    # [ARTICLE CONCEPT: Master Key Derivation]
    # PBKDF2 (Password-Based Key Derivation Function 2) makes brute-forcing
    # master passwords much harder by adding computational cost (iterations)
    # and uniqueness (salt).
    return hashlib.pbkdf2_hmac(
        'sha256',                    # Hash algorithm
        password.encode('utf-8'),    # Master password as bytes
        salt,                        # Unique salt for this password
        KEY_DERIVATION_ITERATIONS,   # Number of iterations (higher is more secure)
        dklen=KEY_LENGTH             # Desired length of the derived key
    )

def generate_strong_password(length=PASSWORD_LENGTH) -> str:
    """
    Generates a strong, random password using characters from different sets.
    """
    # [ARTICLE CONCEPT: Strong Password Generation]
    # Uses secrets module for cryptographically strong random numbers.
    # Ensures a mix of character types for better entropy.
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(alphabet) for i in range(length))
        # Ensure the password contains at least one uppercase, one lowercase,
        # one digit, and one punctuation character.
        if (any(c.islower() for c in password) and
                any(c.isupper() for c in password) and
                any(c.isdigit() for c in password) and
                any(c in string.punctuation for c in password)):
            return password

def set_master_password(password: str):
    """Sets and derives the global master encryption key."""
    global master_key_salt, master_encryption_key
    master_key_salt = generate_salt()
    master_encryption_key = derive_key(password, master_key_salt)
    print("Master password set and key derived.")

def add_password_entry(service_name: str, master_password_input: str):
    """
    Adds a new password entry to the vault.
    In a real app, the generated password would be encrypted using master_encryption_key.
    """
    if not master_encryption_key:
        print("Error: Master password not set. Please set it first.")
        return

    # Verify master password before adding/retrieving
    if derive_key(master_password_input, master_key_salt) != master_encryption_key:
        print("Error: Incorrect master password.")
        return

    generated_pw = generate_strong_password()
    
    # [ARTICLE CONCEPT: Simulated Secure Storage]
    # In a real password manager, 'generated_pw' would be encrypted using
    # 'master_encryption_key' (e.g., with AES-256 GCM) and then stored.
    # For this stdlib-only example, we store it in plain text in memory.
    vault[service_name] = {
        'password_placeholder': generated_pw # In real app: actual ciphertext
    }
    print(f"Password for '{service_name}' generated and added (simulated storage).")
    print(f"Generated password: {generated_pw}") # Display for demo, not in real app

def get_password_entry(service_name: str, master_password_input: str) -> str | None:
    """
    Retrieves a password entry from the vault.
    In a real app, the stored ciphertext would be decrypted using master_encryption_key.
    """
    if not master_encryption_key:
        print("Error: Master password not set.")
        return None

    # Verify master password before adding/retrieving
    if derive_key(master_password_input, master_key_salt) != master_encryption_key:
        print("Error: Incorrect master password.")
        return None

    entry = vault.get(service_name)
    if entry:
        # [ARTICLE CONCEPT: Simulated Retrieval]
        # In a real password manager, 'entry['password_placeholder']' would be
        # decrypted using 'master_encryption_key' to reveal the actual password.
        return entry['password_placeholder'] # In real app: actual decrypted password
    else:
        print(f"No entry found for '{service_name}'.")
        return None

def main():
    print("--- Simple Password Manager Core Concepts Demo ---")

    # 1. Set Master Password
    print("\n--- Step 1: Set Master Password ---")
    mp = input("Enter a MASTER password: ")
    set_master_password(mp)

    # 2. Add a new password entry
    print("\n--- Step 2: Add a new password entry ---")
    service1 = "my_social_media"
    mp_verify = input(f"Enter MASTER password to add '{service1}': ")
    add_password_entry(service1, mp_verify)

    # 3. Retrieve a password entry
    print("\n--- Step 3: Retrieve a password entry ---")
    mp_verify = input(f"Enter MASTER password to retrieve '{service1}': ")
    retrieved_pw = get_password_entry(service1, mp_verify)
    if retrieved_pw:
        print(f"Retrieved password for '{service1}': {retrieved_pw}")

    # 4. Demonstrate incorrect master password
    print("\n--- Step 4: Demonstrate incorrect master password ---")
    print("Attempting to retrieve with wrong master password...")
    get_password_entry(service1, "wrong_master_password")

    # 5. Add another entry
    print("\n--- Step 5: Add another entry ---")
    service2 = "my_banking_app"
    mp_verify = input(f"Enter MASTER password to add '{service2}': ")
    add_password_entry(service2, mp_verify)

    # 6. Retrieve the second entry
    print("\n--- Step 6: Retrieve the second entry ---")
    mp_verify = input(f"Enter MASTER password to retrieve '{service2}': ")
    retrieved_pw = get_password_entry(service2, mp_verify)
    if retrieved_pw:
        print(f"Retrieved password for '{service2}': {retrieved_pw}")

    print("\n--- Demo End ---")

if __name__ == "__main__":
    main()
