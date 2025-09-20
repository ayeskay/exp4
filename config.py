# config.py

# Network Configuration
THIRD_PARTY_HOST = 'localhost'
THIRD_PARTY_PORT = 4444
SENDER_PORT = 2222
RECEIVER_PORT = 3333

# RSA Key Sizes (in bits)
RSA_KEY_SIZE = 1024 # Increased from 32. For demonstration; real-world keys are 1024, 2048 bits
RSA_PRIME_SIZE = RSA_KEY_SIZE // 2

# Symmetric Key Size (in characters)
SYMMETRIC_KEY_SIZE = 4 # e.g., 200-300 characters as suggested

# Message Size Requirement
MIN_MESSAGE_SIZE = 10000 # > 10K letters

# Character Encoding
CHAR_ENCODING_START = 32 # Space
CHAR_ENCODING_END = 126 # Tilde (~)
ENCODING_BASE = CHAR_ENCODING_END - CHAR_ENCODING_START + 1

# Delimiters for network messages
DELIMITER = "|"
END_MARKER = "||END||"