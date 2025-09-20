# peer.py
import socket
import threading
import time
import os
import datetime
from rsa_utils import generate_keys, encrypt, decrypt, text_to_number, number_to_text, generate_symmetric_key, simple_sym_encrypt, simple_sym_decrypt, sign, verify_signature
from config import THIRD_PARTY_HOST, THIRD_PARTY_PORT, DELIMITER, END_MARKER, RSA_KEY_SIZE, SYMMETRIC_KEY_SIZE, MIN_MESSAGE_SIZE
from logger_utils import log_sender_output, log_receiver_output

class Peer:
    def __init__(self):
        self.identity = None
        self.my_port = None
        self.private_key = None
        self.public_key = None
        self.keyring = {}
        self.symmetric_key = None
        self.last_key_exchange_time = None
        self.session_timeout_seconds = 60
        self.running = True

    def run(self):
        self.identity = input("Enter your identity (e.g., alice): ").strip()
        temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        temp_socket.bind(('', 0))
        self.my_port = temp_socket.getsockname()[1]
        temp_socket.close()
        print(f"Starting peer '{self.identity}' on port {self.my_port}")
        self.listener_thread = threading.Thread(target=self.start_listening)
        self.listener_thread.daemon = True
        self.listener_thread.start()
        print("[Peer] Generating RSA keys...")
        self.public_key, self.private_key = generate_keys(RSA_KEY_SIZE)
        print(f"[Peer] Generated keys. Public: {self.public_key}")
        while True:
            print("\n--- Peer Menu ---")
            print("1. Register with Third Party")
            print("2. View Keyring")
            print("3. Send Message to Another Peer")
            print("4. Exit")
            choice = input("Enter your choice (1-4): ").strip()
            if choice == '1':
                self.register_with_third_party()
            elif choice == '2':
                self.view_keyring()
            elif choice == '3':
                self.send_message()
            elif choice == '4':
                print("[Peer] Stopping...")
                self.running = False
                # No need to join a daemon thread
                break
            else:
                print("[Peer] Invalid choice.")

    def view_keyring(self):
        print("\n--- My Keyring ---")
        if not self.keyring:
            print("Keyring is empty.")
        else:
            for identity, data in self.keyring.items():
                pub_key, port = data
                print(f"Identity: {identity} | Public Key: {pub_key} | Port: {port}")
        print("------------------\n")

    def register_with_third_party(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((THIRD_PARTY_HOST, THIRD_PARTY_PORT))
                e, n = self.public_key
                message = f"REGISTER{DELIMITER}{self.identity}{DELIMITER}{e}{DELIMITER}{n}{DELIMITER}{self.my_port}{END_MARKER}"
                s.sendall(message.encode())
                print(f"[Peer] Sent registration: {message}")
                data = s.recv(4096)
                response = data.decode().rstrip(END_MARKER)
                print(f"[Peer] Received registration response: {response}")
                if response.startswith("ACK"):
                    print("[Peer] Successfully registered with Third Party.")
                else:
                    print(f"[Peer] Registration failed: {response}")
        except Exception as e:
            print(f"[Peer] Error during registration: {e}")

    def get_key_from_tpe(self, target_identity):
        if target_identity in self.keyring:
            print(f"[Peer] Found {target_identity}'s key in local keyring.")
            return self.keyring[target_identity]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((THIRD_PARTY_HOST, THIRD_PARTY_PORT))
                message = f"LOOKUP{DELIMITER}{target_identity}{END_MARKER}"
                s.sendall(message.encode())
                print(f"[Peer] Sent lookup request for {target_identity}")
                data = s.recv(4096)
                response = data.decode().rstrip(END_MARKER)
                print(f"[Peer] Received lookup response: {response}")
                if not response.startswith("LOOKUP_RESPONSE"):
                    print(f"[Peer] Failed to get key: {response}")
                    return None, None
                parts = response.split(DELIMITER)
                receiver_e, receiver_n, receiver_port = map(int, parts[1:4])
                self.keyring[target_identity] = ((receiver_e, receiver_n), receiver_port)
                print(f"[Peer] Added {target_identity}'s key to keyring.")
                return (receiver_e, receiver_n), receiver_port
        except Exception as e:
            print(f"[Peer] Error during key lookup: {e}")
            return None, None

    def is_session_timed_out(self):
        if self.last_key_exchange_time is None:
            return False
        elapsed_time = (datetime.datetime.now() - self.last_key_exchange_time).total_seconds()
        return elapsed_time > self.session_timeout_seconds

    def send_message(self):
        receiver_identity = input("[Peer] Enter receiver's identity: ").strip()
        if not receiver_identity:
            print("[Peer] Receiver identity cannot be empty.")
            return
        receiver_pub_key, receiver_port = self.get_key_from_tpe(receiver_identity)
        if not receiver_pub_key:
            return
        receiver_e, receiver_n = receiver_pub_key

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((THIRD_PARTY_HOST, receiver_port))
                
                if self.is_session_timed_out() or self.symmetric_key is None:
                    print("[Peer] Generating new symmetric key (Handshake/Re-keying)...")
                    self.symmetric_key = generate_symmetric_key(SYMMETRIC_KEY_SIZE)
                    try:
                        sym_key_num = text_to_number(self.symmetric_key, 95)
                        if sym_key_num >= receiver_n:
                            print("[Peer] Error: Symmetric key is too large for the recipient's RSA modulus.")
                            self.symmetric_key = None
                            return
                        encrypted_sym_key_num = encrypt(sym_key_num, receiver_e, receiver_n)
                        # **FIX: Send identity along with the key**
                        key_message = f"KEY{DELIMITER}{self.identity}{DELIMITER}{encrypted_sym_key_num}{END_MARKER}"
                        s.sendall(key_message.encode())
                        print(f"[Peer] Sent encrypted symmetric key to {receiver_identity}.")
                        self.last_key_exchange_time = datetime.datetime.now()
                    except Exception as e:
                        print(f"[Peer] Error during handshake/re-keying: {e}")
                        self.symmetric_key = None
                        return

                message_content = input("[Peer] Enter the message to send: ")
                timestamp = datetime.datetime.now().isoformat()
                encrypted_message = simple_sym_encrypt(message_content, self.symmetric_key)
                signed_text = sign(encrypted_message + timestamp, self.private_key)
                
                log_sender_output(self.identity, receiver_identity, message_content, signed_text, encrypted_message)
                
                # **FIX: Send identity with the message**
                msg_message = f"MSG{DELIMITER}{self.identity}{DELIMITER}{encrypted_message}{DELIMITER}{signed_text}{DELIMITER}{timestamp}{END_MARKER}"
                s.sendall(msg_message.encode())
                print(f"[Peer] Sent encrypted and signed message to {receiver_identity}.")

                close_notify = f"CLOSE_NOTIFY{DELIMITER}{self.identity}{DELIMITER}{sign('CLOSE_NOTIFY', self.private_key)}{END_MARKER}"
                s.sendall(close_notify.encode())
                print("[Peer] Sent close notify message.")
        except Exception as e:
            print(f"[Peer] Error sending message: {e}")

    def start_listening(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((THIRD_PARTY_HOST, self.my_port))
            s.listen()
            print(f"[Peer] Listening for incoming messages on port {self.my_port}")
            while self.running:
                try:
                    s.settimeout(1.0) 
                    conn, addr = s.accept()
                    threading.Thread(target=self.handle_connection, args=(conn, addr)).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"[Peer] Listening error: {e}")

    def handle_connection(self, conn, addr):
        with conn:
            try:
                inbox = b""
                while True:
                    packet = conn.recv(4096)
                    if not packet:
                        break
                    inbox += packet
                    while END_MARKER.encode() in inbox:
                        full_message, inbox = inbox.split(END_MARKER.encode(), 1)
                        self.process_message(full_message.decode())
            except Exception as e:
                print(f"[Peer] Error handling connection from {addr}: {e}")

    def process_message(self, full_message):
        parts = full_message.split(DELIMITER)
        command = parts[0]

        if command == "KEY":
            # **FIX: KEY format is now KEY|sender_identity|encrypted_sym_key_num**
            if len(parts) < 3:
                print(f"[Peer] Malformed KEY message: {full_message}")
                return
            sender_identity, encrypted_sym_key_str = parts[1], parts[2]
            print(f"\n[Peer] Received KEY from {sender_identity}")
            
            # Key is not signed, but we now know who it's from.
            # In a real system, the KEY message itself should be signed.
            
            try:
                encrypted_sym_key_num = int(encrypted_sym_key_str)
                decrypted_sym_key_num = decrypt(encrypted_sym_key_num, *self.private_key)
                self.symmetric_key = number_to_text(decrypted_sym_key_num, 95)
                self.last_key_exchange_time = datetime.datetime.now()
                print(f"[Peer] Successfully decrypted symmetric key from {sender_identity}.")
            except (ValueError, TypeError) as e:
                print(f"[Peer] Error processing symmetric key from {sender_identity}: {e}")

        elif command == "MSG":
            # **FIX: MSG format is now MSG|sender_identity|encrypted_message|signature|timestamp**
            if len(parts) < 5:
                print(f"[Peer] Malformed MSG message: {full_message}")
                return
            
            sender_identity, encrypted_message, signature, timestamp = parts[1], parts[2], parts[3], parts[4]
            print(f"\n[Peer] Received MSG from {sender_identity}")

            sender_pub_key, _ = self.get_key_from_tpe(sender_identity)
            if not sender_pub_key:
                print(f"[Peer] Could not get public key for '{sender_identity}'. Dropping message.")
                return

            if not verify_signature(encrypted_message + timestamp, signature, sender_pub_key):
                print("[Peer] !!! DIGITAL SIGNATURE VERIFICATION FAILED !!!")
                return
            
            print("[Peer] Digital signature verified successfully.")

            try:
                msg_time = datetime.datetime.fromisoformat(timestamp)
                if (datetime.datetime.now() - msg_time).total_seconds() > 60: # 1 minute tolerance
                    print("[Peer] Replay attack detected: Message is too old.")
                    return
            except ValueError:
                print(f"[Peer] Invalid timestamp format: {timestamp}")
                return

            if self.symmetric_key:
                decrypted_message = simple_sym_decrypt(encrypted_message, self.symmetric_key)
                print("\n--- Decrypted Message ---")
                print(f"From: {sender_identity}")
                print(f"Plain Text: {decrypted_message}")
                print("-------------------------\n")
                log_receiver_output(self.identity, decrypted_message, True, decrypted_message)
            else:
                print("[Peer] Received message but no symmetric key is established.")

        elif command == "CLOSE_NOTIFY":
            if len(parts) < 3:
                print(f"[Peer] Malformed CLOSE_NOTIFY message: {full_message}")
                return
            sender_identity, signature = parts[1], parts[2]
            sender_pub_key, _ = self.get_key_from_tpe(sender_identity)
            if sender_pub_key and verify_signature("CLOSE_NOTIFY", signature, sender_pub_key):
                print(f"\n[Peer] Received valid close notify from {sender_identity}. Session terminated.")
            else:
                print(f"\n[Peer] Received INVALID close notify from {sender_identity}.")
            # The connection will be closed by the handler.

        else:
            print(f"[Peer] Unknown command received: {command}")


if __name__ == "__main__":
    peer = Peer()
    peer.run()