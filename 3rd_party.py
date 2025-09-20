# 3rd_party.py
import socket
import threading
from config import THIRD_PARTY_HOST, THIRD_PARTY_PORT, DELIMITER, END_MARKER

class ThirdParty:
    def __init__(self):
        self.registered_entities = {}
        self.lock = threading.Lock()

    def handle_client(self, conn, addr):
        try:
            print(f"[Third Party] Connected by {addr}")
            data = b""
            while not data.endswith(END_MARKER.encode()):
                packet = conn.recv(4096)
                if not packet:
                    break
                data += packet
            full_message = data.decode().rstrip(END_MARKER)
            print(f"[Third Party] Received: {full_message}")

            parts = full_message.split(DELIMITER)
            command = parts[0]

            if command == "REGISTER":
                identity = parts[1]
                e = int(parts[2])
                n = int(parts[3])
                port = int(parts[4])

                with self.lock:
                    self.registered_entities[identity] = {'pub_key': (e, n), 'port': port}
                print(f"[Third Party] Registered {identity} with key ({e}, {n}) on port {port}")
                response = f"ACK{DELIMITER}Registered successfully.{END_MARKER}"

            elif command == "LOOKUP":
                identity = parts[1]
                print(f"[Third Party] Lookup request for {identity}")
                with self.lock:
                    if identity in self.registered_entities:
                        e, n = self.registered_entities[identity]['pub_key']
                        port = self.registered_entities[identity]['port']
                        response = f"LOOKUP_RESPONSE{DELIMITER}{e}{DELIMITER}{n}{DELIMITER}{port}{END_MARKER}"
                    else:
                        response = f"ERROR{DELIMITER}Identity not found.{END_MARKER}"
            else:
                response = f"ERROR{DELIMITER}Unknown command.{END_MARKER}"

            conn.sendall(response.encode())
            print(f"[Third Party] Sent response: {response}")

        except Exception as e:
            print(f"[Third Party] Error handling client {addr}: {e}")
            error_response = f"ERROR{DELIMITER}Internal server error.{END_MARKER}"
            try:
                conn.sendall(error_response.encode())
            except:
                pass
        finally:
            conn.close()
            print(f"[Third Party] Connection with {addr} closed.")

    def start_server(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((THIRD_PARTY_HOST, THIRD_PARTY_PORT))
            s.listen()
            print(f"[Third Party] Server listening on {THIRD_PARTY_HOST}:{THIRD_PARTY_PORT}")
            try:
                while True:
                    conn, addr = s.accept()
                    client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                    client_thread.daemon = True
                    client_thread.start()
            except KeyboardInterrupt:
                print("\n[Third Party] Server shutting down.")
            finally:
                s.close()

if __name__ == "__main__":
    tp = ThirdParty()
    tp.start_server()
