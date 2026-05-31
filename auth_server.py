from flask import Flask
import os

app = Flask(__name__)

@app.route('/')
def home():
    return 'OK'

@app.route('/api/health')
def health():
    return {'status': 'healthy'}

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
