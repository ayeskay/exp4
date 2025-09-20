# logger_utils.py
import time

STUDENT_NAME = "AdityaKhabiya"  # Replace with actual student name
STUDENT_UID = "2023300110"    # Replace with actual student UID
OUTPUT_FILE = f"Exp04-{STUDENT_NAME}-{STUDENT_UID}-Input-Output.txt"

def log_to_file(content):
    with open(OUTPUT_FILE, 'a') as f:
        f.write(content + '\n')

def log_sender_output(sender_id, receiver_id, plaintext, signed_text, encrypted_text):
    log_content = (
        f"\n--- SENDER OUTPUT ({sender_id} -> {receiver_id}) ---\n"
        f"Timestamp: {time.time()}\n"
        f"Plain Text: {plaintext}\n"
        f"Digitally Signed Text: {signed_text}\n"
        f"Encrypted Text: {encrypted_text}\n"
        "--------------------------------------------------\n"
    )
    print(log_content)
    log_to_file(log_content)

def log_receiver_output(receiver_id, decrypted_text, signature_valid, plaintext):
    log_content = (
        f"\n--- RECEIVER OUTPUT ({receiver_id}) ---\n"
        f"Timestamp: {datetime.datetime.now()}\n"
        f"Decrypted Text: {decrypted_text}\n"
        f"Digital Signature Verification: {signature_valid}\n"
        f"Plain Text: {plaintext}\n"
        "------------------------------------------\n"
    )
    print(log_content)
    log_to_file(log_content)
