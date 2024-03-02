# jwks_server.py
from flask import Flask, request, jsonify
from Crypto.PublicKey import RSA
from datetime import datetime, timedelta
import jwt

app = Flask(__name__)

# RSA key pair generation
def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# JWKS endpoint
@app.route('/jwks', methods=['GET'])
def jwks():
    current_time = datetime.utcnow()

    # Generate a key pair
    private_key, public_key = generate_key_pair()
    kid = str(hash(public_key))  # Use hash of public key as kid
    expiry_time = current_time + timedelta(days=30)  # Key expiry in 30 days

    jwks = {
        'keys': [
            {
                'kid': kid,
                'kty': 'RSA',
                'alg': 'RS256',
                'use': 'sig',
                'n': public_key.decode('utf-8'),
                'e': 'AQAB',
                'exp': int(expiry_time.timestamp())
            }
        ]
    }

    return jsonify(jwks)

# Authentication endpoint
@app.route('/auth', methods=['POST'])
def authenticate():
    expired = request.args.get('expired', False)

    if expired:
        # If expired query parameter is present, sign with an expired key
        private_key, _ = generate_key_pair()
        expiry_time = datetime.utcnow() - timedelta(days=1)  # Key expired yesterday
    else:
        # Sign with a valid key
        private_key, _ = generate_key_pair()
        expiry_time = datetime.utcnow() + timedelta(days=1)  # Key expiry in 1 day

    payload = {'sub': 'fake_user', 'exp': int(expiry_time.timestamp())}
    token = jwt.encode(payload, private_key, algorithm='RS256')

    return jsonify({'token': token.decode('utf-8')})

if __name__ == '__main__':
    app.run(port=8080)
