import hashlib
import binascii
import hmac

def pbkdf2_hash(password: str, salt: bytes, iterations: int = 100000, dklen: int = 32) -> bytes:
    """Generate PBKDF2 hash with the given password, salt, and iterations."""
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen)

def pbkdf2_verify(password: str, salt_hex: str, hash_hex: str, iterations: int = 100000, dklen: int = 32) -> bool:
    """Verify if the given password generates the same hash as the stored hash."""
    # Decode the salt and hash from hexadecimal
    salt = binascii.unhexlify(salt_hex)
    stored_hash = binascii.unhexlify(hash_hex)
    
    # Generate the PBKDF2 hash with the same parameters
    generated_hash = pbkdf2_hash(password, salt, iterations, dklen)
    
    # Compare the generated hash with the stored hash
    return hmac.compare_digest(generated_hash, stored_hash)

def crack_password(username, wordlist_file: str, salt_hex: str, hash_hex: str, iterations: int = 100000, dklen: int = 32):
    """Attempt to crack the password using a wordlist."""
    with open(wordlist_file, 'r') as file:
        for line in file:
            password = line.strip()  # Read password from file and strip any extra whitespace
            
            # Generate hash and check length before comparison
            test_hash = pbkdf2_hash(password, binascii.unhexlify(salt_hex), iterations, dklen)
            
            if len(test_hash) != len(binascii.unhexlify(hash_hex)):
                continue  # Skip if the length does not match

            if pbkdf2_verify(password, salt_hex, hash_hex, iterations, dklen):
                print(f"Password found for {username}: {password}")
                return password
        print("Password for {username} not found in the wordlist.")
        return None

# Example usage
username='emily'
salt_hex = '227d873cca89103cd83a976bdac52486'  # The salt used during hashing, in hexadecimal format
stored_hash_hex = '97907280dc24fe517c43475bd218bfad56c25d4d11037d8b6da440efd4d691adfead40330b2aa6aaf1f33621d0d73228fc16'  # The stored hash from PBKDF2, in hexadecimal format
iterations = 50000  # Number of iterations used in PBKDF2
derived_key_length = 50  # Length of the derived key in bytes (e.g., 32 bytes for SHA-256)
wordlist_file = '/home/ben/Pentest/WordLists/rockyou.txt'  # Path to the wordlist file

# Start cracking the password
crack_password(username, wordlist_file, salt_hex, stored_hash_hex, iterations, derived_key_length)
