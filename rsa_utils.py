# rsa_utils.py
import random
import math
import secrets # For generating the symmetric key

def is_prime(n, k=5):
    """Miller-Rabin primality test."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as d * 2^r
    r = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime_candidate(length):
    """Generate an odd integer randomly of specified bit length."""
    p = random.getrandbits(length)
    # Apply a mask to set MSB and LSB to 1
    p |= (1 << length - 1) | 1
    return p

def generate_prime_number(length):
    """Generate a prime number of specified bit length."""
    p = 4
    # Keep generating until a prime is found
    while not is_prime(p, 128):
        p = generate_prime_candidate(length)
    return p

def gcd(a, b):
    """Calculate the Greatest Common Divisor of a and b."""
    while b:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    """Calculate the modular inverse of e mod phi using Extended Euclidean Algorithm."""
    # Return x such that (e * x) % phi == 1
    if phi == 0:
        return 1, 0, e
    else:
        x, y, gcd_val = mod_inverse(phi, e % phi)
        return y, x - (e // phi) * y, gcd_val

def extended_gcd(a, b):
    """Extended Euclidean Algorithm."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def modinv(a, m):
    """Modular inverse of a modulo m."""
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist")
    else:
        return x % m

def generate_keys(keysize):
    """Generate RSA public and private keys."""
    # 1. Generate two distinct prime numbers p and q
    p = generate_prime_number(keysize // 2)
    q = generate_prime_number(keysize // 2)
    while p == q:
         q = generate_prime_number(keysize // 2)

    # 2. Compute n = p * q
    n = p * q

    # 3. Compute Euler's totient function phi(n) = (p-1)*(q-1)
    phi = (p - 1) * (q - 1)

    # 4. Choose an integer e such that 1 < e < phi and gcd(e, phi) = 1
    e = 65537 # Common choice for e
    if gcd(e, phi) != 1:
        # If 65537 doesn't work, find another e
        e = random.randrange(1, phi)
        g = gcd(e, phi)
        while g != 1:
            e = random.randrange(1, phi)
            g = gcd(e, phi)

    # 5. Determine d as the modular multiplicative inverse of e modulo phi
    # d = mod_inverse(e, phi) # This might be slow for large numbers
    d = modinv(e, phi) # Using extended gcd

    # Return public key (e, n) and private key (d, n)
    return (e, n), (d, n)

def text_to_number(text, base):
    """Convert text to a number using a base."""
    number = 0
    for char in text:
        # Assuming ASCII values for simplicity, adjust if needed
        # This simple mapping might not work well for large texts directly
        # We'll process blocks for encryption
        char_code = ord(char) - 32 # Map space (32) to 0
        if char_code < 0 or char_code >= base:
             raise ValueError(f"Character '{char}' outside encoding range.")
        number = number * base + char_code
    return number

def number_to_text(number, base):
    """Convert a number back to text using a base."""
    if number == 0:
        return chr(32) # Return space for 0
    text = ""
    while number > 0:
        char_code = number % base
        text = chr(char_code + 32) + text
        number //= base
    return text

def encrypt(plaintext_number, public_key_e, public_key_n):
    """Encrypt a number using RSA."""
    # c = m^e mod n
    return pow(plaintext_number, public_key_e, public_key_n)

def decrypt(ciphertext_number, private_key_d, private_key_n):
    """Decrypt a number using RSA."""
    # m = c^d mod n
    return pow(ciphertext_number, private_key_d, private_key_n)

def sign(message, private_key):
    """Signs a message using the sender's private key."""
    d, n = private_key
    # Convert message to a number
    message_number = text_to_number(message, 95)
    # The signature is the message "encrypted" with the private key
    signature = pow(message_number, d, n)
    return str(signature)

def verify_signature(message, signature, public_key):
    """Verifies a signature using the sender's public key."""
    e, n = public_key
    try:
        signature_number = int(signature)
        # Decrypt the signature with the public key
        decrypted_signature = pow(signature_number, e, n)
        # Convert the original message to a number
        message_number = text_to_number(message, 95)
        # Check if the decrypted signature matches the original message number
        return decrypted_signature == message_number
    except (ValueError, TypeError):
        return False

def generate_symmetric_key(length):
    """Generate a random symmetric key string."""
    # Generate a string of printable ASCII characters
    chars = [chr(i) for i in range(32, 127)] # Space to ~
    return ''.join(secrets.choice(chars) for _ in range(length))

# --- Simple Symmetric Encryption (For demonstration, not secure) ---
def simple_sym_encrypt(plaintext, key):
    """Simple symmetric encryption using key as a numeric shift."""
    key_num = sum(ord(c) for c in key) % 256 # Simple hash of key to a number
    encrypted_chars = []
    for i, char in enumerate(plaintext):
        key_char = key[i % len(key)]
        shift = (ord(key_char) + key_num) % 95 # Range of printable chars (32-126)
        encrypted_char_code = ((ord(char) - 32) + shift) % 95 + 32
        encrypted_chars.append(chr(encrypted_char_code))
    return ''.join(encrypted_chars)

def simple_sym_decrypt(ciphertext, key):
    """Simple symmetric decryption using key as a numeric shift."""
    key_num = sum(ord(c) for c in key) % 256
    decrypted_chars = []
    for i, char in enumerate(ciphertext):
        key_char = key[i % len(key)]
        shift = (ord(key_char) + key_num) % 95
        decrypted_char_code = ((ord(char) - 32) - shift) % 95 + 32
        decrypted_chars.append(chr(decrypted_char_code))
    return ''.join(decrypted_chars)
