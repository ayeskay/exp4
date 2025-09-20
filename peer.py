# peer.py
import socket
import threading
import time
import os
import datetime
from rsa_utils import generate_keys, encrypt, decrypt, text_to_number, number_to_text, generate_symmetric_key, simple_sym_encrypt, simple_sym_decrypt, sign, verify_signature
from config import THIRD_PARTY_HOST, THIRD_PARTY_PORT, DELIMITER, END_MARKER, RSA_KEY_SIZE, SYMMETRIC_KEY_SIZE, MIN_MESSAGE_SIZE
# Import datetime in logger_utils if not already there
from logger_utils import log_sender_output, log_receiver_output

class Peer:
    def __init__(self):
        self.identity = None
        self.my_port = None
        self.private_key = None
        self.public_key = None
        self.keyring = {}
        self.symmetric_key = None
        # --- Session Timeout Feature ---
        self.last_key_exchange_time = None
        self.session_timeout_seconds = 60  # Example: 60 seconds timeout
        # -------------------------------
        self.running = True

    def run(self):
        self.identity = input("Enter your identity (e.g., alice): ").strip()
        # Bind to a random free port
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
                self.listener_thread.join(timeout=2)
                print("[Peer] Exiting.")
                break
            else:
                print("[Peer] Invalid choice.")

    def view_keyring(self):
        print("\n--- My Keyring ---")
        if not self.keyring:
            print("Keyring is empty. Send a message to add keys.")
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
                data = b""
                while not data.endswith(END_MARKER.encode()):
                    packet = s.recv(4096)
                    if not packet: break
                    data += packet
                response = data.decode().rstrip(END_MARKER)
                print(f"[Peer] Received registration response: {response}")
                if response.startswith("ACK"):
                    print("[Peer] Successfully registered with Third Party.")
                    return True
                else:
                    print(f"[Peer] Registration failed: {response}")
                    return False
        except Exception as e:
            print(f"[Peer] Error during registration: {e}")
            return False

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
                data = b""
                while not data.endswith(END_MARKER.encode()):
                    packet = s.recv(4096)
                    if not packet: break
                    data += packet
                response = data.decode().rstrip(END_MARKER)
                print(f"[Peer] Received lookup response: {response}")
                if not response.startswith("LOOKUP_RESPONSE"):
                    print(f"[Peer] Failed to get key: {response}")
                    return None, None
                parts = response.split(DELIMITER)
                receiver_e = int(parts[1])
                receiver_n = int(parts[2])
                receiver_port = int(parts[3])
                self.keyring[target_identity] = ((receiver_e, receiver_n), receiver_port)
                print(f"[Peer] Added {target_identity}'s key to keyring.")
                return (receiver_e, receiver_n), receiver_port
        except Exception as e:
            print(f"[Peer] Error during key lookup: {e}")
            return None, None

    # --- Session Timeout Feature ---
    def is_session_timed_out(self):
        """Check if the current session has timed out."""
        if self.last_key_exchange_time is None:
            return False # No key exchange has happened yet
        elapsed_time = (datetime.datetime.now() - self.last_key_exchange_time).total_seconds()
        return elapsed_time > self.session_timeout_seconds

    def perform_handshake_if_needed(self, receiver_e, receiver_n, receiver_port, receiver_identity):
        """
        Performs the handshake to establish a symmetric key if needed
        (either no key exists, or session timed out).
        Returns True if successful, False otherwise.
        """
        # Check for session timeout
        if self.is_session_timed_out():
            print(f"[Peer] Session timeout detected for {receiver_identity}. Initiating re-keying...")
            self.symmetric_key = None # Clear the old key

        # If no symmetric key exists, perform handshake
        if self.symmetric_key is None:
            print("[Peer] Generating symmetric key...")
            self.symmetric_key = generate_symmetric_key(SYMMETRIC_KEY_SIZE)
            try:
                sym_key_num = text_to_number(self.symmetric_key, 95)
                if sym_key_num >= receiver_n:
                    print("[Peer] Error: Symmetric key too large for RSA modulus.")
                    self.symmetric_key = None
                    return False
                encrypted_sym_key_num = encrypt(sym_key_num, receiver_e, receiver_n)
            except Exception as e:
                print(f"[Peer] Error encrypting symmetric key: {e}")
                self.symmetric_key = None
                return False

            # Simulate sending the KEY message (as in original send_message)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((THIRD_PARTY_HOST, receiver_port)) # Need receiver_port here
                    # This is a simplified simulation. In a full implementation,
                    # the handshake would be part of the message sending process.
                    key_message = f"KEY{DELIMITER}{encrypted_sym_key_num}{END_MARKER}"
                    s.sendall(key_message.encode())
                    print(f"[Peer] Sent encrypted symmetric key to {receiver_identity} (Handshake/Re-keying).")
                    # Update last key exchange time upon successful handshake
                    self.last_key_exchange_time = datetime.datetime.now()
                    return True
            except Exception as e:
                 print(f"[Peer] Error sending handshake/re-keying message: {e}")
                 self.symmetric_key = None
                 return False
        else:
            # Key exists and not timed out, no action needed
            return True
    # -------------------------------

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
                
                # --- Session Timeout Feature (Integrated into send flow) ---
                # Check for timeout or if no key exists
                if self.is_session_timed_out() or self.symmetric_key is None:
                     print("[Peer] Generating new symmetric key (Handshake/Re-keying)...")
                     self.symmetric_key = generate_symmetric_key(SYMMETRIC_KEY_SIZE)
                     try:
                         sym_key_num = text_to_number(self.symmetric_key, 95)
                         if sym_key_num >= receiver_n:
                             print("[Peer] Error: Symmetric key too large for RSA modulus.")
                             self.symmetric_key = None
                             return
                         encrypted_sym_key_num = encrypt(sym_key_num, receiver_e, receiver_n)
                         # Send the KEY message as part of the message flow
                         key_message = f"KEY{DELIMITER}{encrypted_sym_key_num}{END_MARKER}"
                         s.sendall(key_message.encode())
                         print(f"[Peer] Sent encrypted symmetric key to {receiver_identity}.")
                         self.last_key_exchange_time = datetime.datetime.now()
                     except Exception as e:
                         print(f"[Peer] Error during handshake/re-keying: {e}")
                         self.symmetric_key = None
                         return

                # --- MOVED LOGIC STARTS HERE ---
                # Now that the key is guaranteed to exist, get message and encrypt
                message_content = input("[Peer] Enter the message to send: ")
                try:
                    timestamp = datetime.datetime.now().isoformat()
                    encrypted_message = simple_sym_encrypt(message_content, self.symmetric_key)
                    signed_text = sign(encrypted_message + timestamp, self.private_key)
                    # Log sender's output
                    log_sender_output(self.identity, receiver_identity, message_content, signed_text, encrypted_message)
                except Exception as e:
                    print(f"[Peer] Error encrypting/signing message: {e}")
                    return
                # --- MOVED LOGIC ENDS HERE ---

                # Step 2: Send the MSG message on the same connection
                msg_message = f"MSG{DELIMITER}{encrypted_message}{DELIMITER}{signed_text}{DELIMITER}{timestamp}{END_MARKER}"
                s.sendall(msg_message.encode())
                print(f"[Peer] Sent encrypted and signed message to {receiver_identity}.")

                # Step 3: Send the CLOSE_NOTIFY on the same connection
                close_notify = f"CLOSE_NOTIFY{DELIMITER}{self.identity}{DELIMITER}{sign('CLOSE_NOTIFY', self.private_key)}{END_MARKER}"
                s.sendall(close_notify.encode())
                print("[Peer] Sent close notify message.")
        except Exception as e:
            print(f"[Peer] Error sending messages: {e}")

    def start_listening(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((THIRD_PARTY_HOST, self.my_port))
            s.listen()
            print(f"[Peer] Listening for incoming messages on port {self.my_port}")
            try:
                while self.running:
                    s.settimeout(1.0)
                    try:
                        conn, addr = s.accept()
                        sender_thread = threading.Thread(target=self.handle_connection, args=(conn, addr))
                        sender_thread.daemon = True
                        sender_thread.start()
                    except socket.timeout:
                        continue
            except Exception as e:
                if self.running:
                     print(f"[Peer] Error in listening socket: {e}")
            finally:
                s.close()
                print(f"[Peer] Stopped listening on port {self.my_port}")

    def handle_connection(self, conn, addr):
        try:
            inbox = b""
            while True:
                packet = conn.recv(4096)
                if not packet:
                    break
                inbox += packet
                while END_MARKER.encode() in inbox:
                    full_message, inbox = inbox.split(END_MARKER.encode(), 1)
                    full_message = full_message.decode()
                    
                    # --- CORRECTED PARSING ---
                    # Split the entire message by DELIMITER to get all parts
                    parts = full_message.split(DELIMITER)
                    # Check if the message has at least a command part
                    if len(parts) < 1:
                        print(f"[Peer] Malformed message received (no command). Cannot parse: {full_message}")
                        continue
                    
                    command = parts[0]
                    # --- END OF CORRECTED PARSING ---
                    
                    if command == "KEY":
                        # KEY format: KEY|encrypted_sym_key_num
                        if len(parts) < 2:
                             print(f"[Peer] Malformed KEY message received. Expected 2 parts, got {len(parts)}. Message: {full_message}")
                             continue
                        encrypted_sym_key_str = parts[1]
                        try:
                            encrypted_sym_key_num = int(encrypted_sym_key_str)
                        except ValueError:
                            print(f"[Peer] Invalid encrypted symmetric key number in KEY message: {encrypted_sym_key_str}")
                            continue
                        d, n = self.private_key
                        try:
                            decrypted_sym_key_num = decrypt(encrypted_sym_key_num, d, n)
                            self.symmetric_key = number_to_text(decrypted_sym_key_num, 95)
                            # --- Session Timeout Feature ---
                            self.last_key_exchange_time = datetime.datetime.now()
                            # -------------------------------
                            print(f"\n[Peer] Received and decrypted symmetric key.")
                        except Exception as e:
                             print(f"[Peer] Error decrypting symmetric key: {e}")
                             self.symmetric_key = None # Clear key on error
                             
                    elif command == "MSG":
                        # MSG format: MSG|encrypted_message|signature|timestamp
                        if len(parts) < 4:
                            print(f"[Peer] Malformed MSG message received. Expected 4 parts, got {len(parts)}. Message: {full_message}")
                            continue
                        
                        # --- CORRECTLY UNPACK MSG PARTS ---
                        _, encrypted_message, signature, timestamp = parts # _ is 'MSG'
                        # --- END OF CORRECT UNPACKING ---
                        
                        # --- Sender Identity Issue ---
                        # The sender identity needs to be determined.
                        # Placeholder - This is a limitation in the current protocol design.
                        # A better approach would be to include sender identity in the MSG or KEY message.
                        sender_identity = "alice"  # Default placeholder - Needs improvement
                        # --------------------------
                        
                        sender_pub_key, _ = self.get_key_from_tpe(sender_identity)
                        if not sender_pub_key:
                            print(f"[Peer] Could not retrieve public key for sender '{sender_identity}'. Skipping message.")
                            continue # Skip processing if key retrieval fails

                        signature_valid = verify_signature(encrypted_message + timestamp, signature, sender_pub_key)
                        
                        try:
                            msg_time = datetime.datetime.fromisoformat(timestamp)
                            is_old = (datetime.datetime.now() - msg_time).total_seconds() > 2
                            if is_old:
                                print("[Peer] Replay attack detected: Message is too old!")
                                continue
                        except ValueError:
                            print(f"[Peer] Invalid timestamp format: {timestamp}")
                            continue # Skip message with invalid timestamp

                        if not signature_valid:
                            print("[Peer] Digital signature verification failed!")
                            continue
                        
                        if self.symmetric_key:
                            try:
                                decrypted_message = simple_sym_decrypt(encrypted_message, self.symmetric_key)
                                print("\n--- Decrypted Message ---")
                                print("Plain Text:", decrypted_message)
                                print("Digital Signature Verification:", signature_valid)
                                print("Decrypted Text:", decrypted_message)
                                print("--- End of Message ---\n")
                                
                                # --- Call the logger with error handling ---
                                try:
                                    log_receiver_output(self.identity, decrypted_message, signature_valid, decrypted_message)
                                    print("[DEBUG] Receiver output logged successfully.") # Optional confirmation
                                except Exception as log_error:
                                    print(f"[ERROR] Failed to log receiver output: {log_error}")
                                # ------------------------------------------
                                
                            except Exception as decrypt_error:
                                print(f"[Peer] Error decrypting message content: {decrypt_error}")
                        else:
                            print("[Peer] Received message but symmetric key is not available.")
                            
                    elif command == "CLOSE_NOTIFY":
                        # CLOSE_NOTIFY format: CLOSE_NOTIFY|sender_identity|signature
                        if len(parts) < 3:
                             print(f"[Peer] Malformed CLOSE_NOTIFY message received. Expected 3 parts, got {len(parts)}. Message: {full_message}")
                             continue
                        sender_identity = parts[1]
                        signature = parts[2]
                        sender_pub_key, _ = self.get_key_from_tpe(sender_identity)
                        if not sender_pub_key:
                            print(f"[Peer] Could not retrieve public key for sender '{sender_identity}' for CLOSE_NOTIFY.")
                            # Still print the notification even if key retrieval fails
                            print(f"\n[Peer] Received close notify from {sender_identity} (key unavailable). Session terminated.")
                            break
                        if verify_signature("CLOSE_NOTIFY", signature, sender_pub_key):
                            print(f"\n[Peer] Received valid close notify from {sender_identity}. Session terminated.")
                        else:
                            print(f"\n[Peer] Received invalid close notify from {sender_identity}.")
                        break
                    else:
                        print(f"[Peer] Unknown command received: {command}")
                        
                # This check seems redundant or incorrect based on the loop logic
                # if END_MARKER.encode() not in inbox and "CLOSE_NOTIFY" in full_message:
                #     break
                # The inner while loop processes messages until inbox is drained.
                # The outer while True loop breaks when CLOSE_NOTIFY is processed or connection closes.
                
        except Exception as e:
            print(f"[Peer] Error handling connection from {addr}: {e}")
        finally:
            conn.close()

if __name__ == "__main__":
    peer = Peer()
    peer.run()