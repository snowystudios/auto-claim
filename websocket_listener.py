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

# File‑based session store (works across processes on the same server)
SESSION_FILE = "/tmp/auth_sessions.json"
RESULT_FILE = "/tmp/auth_results.json"

def save_session(session_id, fingerprint):
    data = {}
    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE, 'r') as f:
            data = json.load(f)
    data[session_id] = fingerprint
    with open(SESSION_FILE, 'w') as f:
        json.dump(data, f)

def save_result(session_id, user_data):
    data = {}
    if os.path.exists(RESULT_FILE):
        with open(RESULT_FILE, 'r') as f:
            data = json.load(f)
    data[session_id] = user_data
    with open(RESULT_FILE, 'w') as f:
        json.dump(data, f)

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

    def run(self):
        print(f"[Listener] Starting WebSocket for session {self.session_id}")
        self.ws = websocket.WebSocketApp(
            self.WS_ENDPOINT,
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
            header={'Origin': 'https://discord.com'}
        )
        self.ws.run_forever()

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
        pub = self.key.publickey().export_key().decode()
        pub_key = ''.join(pub.split('\n')[1:-1])
        self.send('init', {'encoded_public_key': pub_key})

    def on_message(self, ws, message):
        data = json.loads(message)
        op = data.get('op')

        if op == 'hello':
            self.heartbeat_interval = data.get('heartbeat_interval') / 1000
            self.last_heartbeat = time.time()
            threading.Thread(target=self.heartbeat_sender, daemon=True).start()

        elif op == 'nonce_proof':
            nonce = data.get('encrypted_nonce')
            decrypted = self.decrypt_payload(nonce)
            proof = SHA256.new(decrypted).digest()
            proof = base64.urlsafe_b64encode(proof).decode().rstrip('=')
            self.send('nonce_proof', {'proof': proof})

        elif op == 'pending_remote_init':
            self.current_fingerprint = data.get('fingerprint')
            auth_url = f"https://discord.com/ra/{self.current_fingerprint}"
            save_session(self.session_id, auth_url)
            print(f"[Listener] Session {self.session_id} -> {auth_url}")

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
            print(f"[Listener] Got user {values[3]}#{values[1]} for {self.session_id}")

        elif op == 'pending_login':
            ticket = data.get('ticket')
            try:
                resp = requests.post(self.LOGIN_ENDPOINT, json={'ticket': ticket}, timeout=10)
                if resp.status_code == 200:
                    encrypted_token = resp.json().get('encrypted_token')
                    token = self.decrypt_payload(encrypted_token).decode()
                    self.user_data['token'] = token
                    save_result(self.session_id, self.user_data)
                    print(f"[Listener] Token saved for {self.session_id}")
                    self.should_stop = True
                    ws.close()
                else:
                    print(f"[Listener] Token exchange failed: {resp.text}")
            except Exception as e:
                print(f"[Listener] Token exchange error: {e}")

    def on_error(self, ws, error):
        print(f"[Listener] WebSocket error: {error}")

    def on_close(self, ws, status, msg):
        print(f"[Listener] WebSocket closed: {status} {msg}")

def start_session(session_id):
    """Start a WebSocket session for the given session_id in the background."""
    ws_client = DiscordAuthWebsocket(session_id)
    thread = threading.Thread(target=ws_client.run, daemon=True)
    thread.start()
    # Wait a few seconds for the fingerprint to appear
    timeout = 10
    while timeout > 0:
        if os.path.exists(SESSION_FILE):
            with open(SESSION_FILE, 'r') as f:
                data = json.load(f)
                if session_id in data:
                    return data[session_id]  # auth_url
        time.sleep(0.2)
        timeout -= 0.2
    return None

if __name__ == "__main__":
    # This script is meant to be run as a background process.
    # It will keep running forever, listening for new sessions.
    print("[Listener] Ready to accept sessions")
    while True:
        time.sleep(60)   # Keep alive
