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
import os

app = Flask(__name__)
CORS(app)

active_sessions = {}
session_results = {}

# Optional: use a proxy to avoid CAPTCHA (uncomment and set env)
PROXY = os.environ.get('PROXY_URL')  # e.g. 'http://user:pass@proxy:port'
PROXIES = {'http': PROXY, 'https': PROXY} if PROXY else None

class DiscordAuth:
    WS_URL = 'wss://remote-auth-gateway.discord.gg/?v=2'
    LOGIN_URL = 'https://discord.com/api/v9/users/@me/remote-auth/login'

    def __init__(self, session_id):
        self.sid = session_id
        self.key = RSA.generate(2048)
        self.cipher = PKCS1_OAEP.new(self.key, hashAlgo=SHA256)
        self.fingerprint = None
        self.ws = None
        self.user_data = None
        self.completed = False

    def run(self):
        self.ws = websocket.WebSocketApp(
            self.WS_URL,
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=lambda ws, err: None,
            on_close=lambda ws, *_: None,
            header={'Origin': 'https://discord.com'}
        )
        self.ws.run_forever()

    def send(self, op, data=None):
        p = {'op': op}
        if data:
            p.update(data)
        if self.ws and self.ws.sock and self.ws.sock.connected:
            self.ws.send(json.dumps(p))

    def on_open(self, ws):
        pub = self.key.publickey().export_key().decode()
        pub_key = ''.join(pub.split('\n')[1:-1])
        self.send('init', {'encoded_public_key': pub_key})

    def on_message(self, ws, msg):
        data = json.loads(msg)
        op = data.get('op')
        if op == 'pending_remote_init':
            self.fingerprint = data['fingerprint']
            active_sessions[self.sid] = f'https://discord.com/ra/{self.fingerprint}'
        elif op == 'pending_ticket':
            enc = data['encrypted_user_payload']
            dec = self.cipher.decrypt(base64.b64decode(enc)).decode()
            vals = dec.split(':')
            self.user_data = {'id': vals[0], 'discriminator': vals[1], 'username': vals[3]}
        elif op == 'pending_login':
            ticket = data['ticket']
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Content-Type': 'application/json',
                'Origin': 'https://discord.com'
            }
            try:
                resp = requests.post(self.LOGIN_URL, json={'ticket': ticket}, headers=headers, timeout=10, proxies=PROXIES)
                if resp.status_code == 200:
                    enc_token = resp.json()['encrypted_token']
                    token = self.cipher.decrypt(base64.b64decode(enc_token)).decode()
                    self.user_data['token'] = token
                    session_results[self.sid] = self.user_data
                    self.completed = True
                    ws.close()
            except:
                pass

    @property
    def public_key(self):
        pub = self.key.publickey().export_key().decode()
        return ''.join(pub.split('\n')[1:-1])

@app.route('/api/create_session', methods=['POST'])
def create():
    sid = secrets.token_urlsafe(16)
    ws_client = DiscordAuth(sid)
    threading.Thread(target=ws_client.run, daemon=False).start()
    # wait for fingerprint
    for _ in range(50):  # max 10 sec
        if sid in active_sessions:
            url = active_sessions.pop(sid)
            return jsonify({'session_id': sid, 'auth_url': url, 'status': 'pending'})
        time.sleep(0.2)
    return jsonify({'error': 'timeout'}), 500

@app.route('/api/check_status/<sid>', methods=['GET'])
def status(sid):
    if sid in session_results:
        return jsonify({'status': 'completed', 'user_data': session_results.pop(sid)})
    return jsonify({'status': 'pending'})

@app.route('/api/health')
def health():
    return {'status': 'healthy'}

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, threaded=True)
