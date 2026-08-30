# Original Flask API from the DSA lab (local/TP use).
# The public demo is the static site (index.html) — no Flask on GitHub Pages.
# Keys are generated in memory or locally; do not commit *.pem files.

from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import sympy
import random
import hashlib
import time
import base64
from cryptography.hazmat.primitives.asymmetric.dsa import generate_parameters
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)
CORS(app)

# Stockage en mémoire pour la démo
keys_store = {}
signatures_store = {}

# ============ FONCTIONS DSA MANUELLES ============

def generate_p(interval_min=20000, interval_max=100000):
    return sympy.randprime(interval_min, interval_max)

def generate_q(p, min_value=50):
    p_divisors = sympy.divisors(p-1)
    prime_divisors = []
    for value in p_divisors:
        if sympy.isprime(value) and value > min_value:
            prime_divisors.append(value)
    if len(prime_divisors) == 0:
        return -1
    else:
        return random.choice(prime_divisors)
    
def generate_alpha(p, q):
    values_list = list(range(2, p-1))
    for value in values_list:
        alpha = pow(value, (p-1)//q, p)
        if alpha != 1 and pow(alpha, q, p) == 1:
            return alpha
    return -1

def generate_private_key(q):
    return random.randint(1, q-1)

def calculate_public_key(alpha, d, p):
    return pow(alpha, d, p)

def get_signature(message, p, q, alpha, d):
    hash_hex = hashlib.sha256(message.encode('utf-8')).hexdigest()
    hash_int = int(hash_hex, 16)

    found_values = False
    while not found_values:
        k = random.randint(1, q-1)
        r = pow(alpha, k, p) % q
        if r != 0:
            found_values = True
        if found_values:
            k_inv = sympy.mod_inverse(k, q)
            s = (k_inv * (hash_int + d * r)) % q
            if s != 0:
                return (r, s)
            else:
                found_values = False

def verify_signature(message, r_s, p, q, alpha, beta):
    r, s = r_s
    if r == 0 or s == 0:
        return False
    
    hash_hex = hashlib.sha256(message.encode('utf-8')).hexdigest()
    hash_int = int(hash_hex, 16)

    w = sympy.mod_inverse(s, q)
    
    u1 = (hash_int * w) % q
    u2 = (r * w) % q

    p_mod_alpha = pow(alpha, u1, p)
    p_mod_beta = pow(beta, u2, p)
    p_mod_AlphaBeta = (p_mod_alpha * p_mod_beta) % p
    v = p_mod_AlphaBeta % q

    return v == r

# ============ ROUTES ============

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/generate-keys', methods=['POST'])
def generate_keys():
    try:
        # Génération des paramètres
        while True:
            p = generate_p()
            q = generate_q(p)
            if q != -1:
                break
        
        alpha = generate_alpha(p, q)
        d = generate_private_key(q)
        beta = calculate_public_key(alpha, d, p)
        
        key_id = str(int(time.time()))
        
        keys_store[key_id] = {
            'p': p,
            'q': q,
            'alpha': alpha,
            'beta': beta,
            'd': d
        }
        
        return jsonify({
            'success': True,
            'key_id': key_id,
            'public_key': {
                'p': str(p),
                'q': str(q),
                'alpha': str(alpha),
                'beta': str(beta)
            },
            'private_key': str(d)
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/sign', methods=['POST'])
def sign_message():
    try:
        data = request.json
        key_id = data.get('key_id')
        message = data.get('message')
        
        if not key_id or key_id not in keys_store:
            return jsonify({'success': False, 'error': 'Clé non trouvée'}), 400
        
        if not message:
            return jsonify({'success': False, 'error': 'Message requis'}), 400
        
        key = keys_store[key_id]
        signature = get_signature(
            message,
            key['p'],
            key['q'],
            key['alpha'],
            key['d']
        )
        
        sig_id = str(int(time.time()))
        signatures_store[sig_id] = {
            'message': message,
            'signature': signature,
            'key_id': key_id
        }
        
        return jsonify({
            'success': True,
            'sig_id': sig_id,
            'signature': {
                'r': str(signature[0]),
                's': str(signature[1])
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/verify', methods=['POST'])
def verify_message():
    try:
        data = request.json
        message = data.get('message')
        r = int(data.get('r'))
        s = int(data.get('s'))
        p = int(data.get('p'))
        q = int(data.get('q'))
        alpha = int(data.get('alpha'))
        beta = int(data.get('beta'))
        
        result = verify_signature(message, (r, s), p, q, alpha, beta)
        
        return jsonify({
            'success': True,
            'valid': result
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/library-generate-keys', methods=['POST'])
def library_generate_keys():
    try:
        params = generate_parameters(key_size=1024, backend=default_backend())
        private_key = params.generate_private_key()
        public_key = private_key.public_key()
        
        # Export en PEM
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        key_id = str(int(time.time()))
        
        keys_store[key_id] = {
            'type': 'library',
            'private_key': private_key,
            'public_key': public_key,
            'private_pem': private_pem,
            'public_pem': public_pem
        }
        
        return jsonify({
            'success': True,
            'key_id': key_id,
            'private_pem': private_pem,
            'public_pem': public_pem
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/library-sign', methods=['POST'])
def library_sign():
    try:
        data = request.json
        key_id = data.get('key_id')
        message = data.get('message')
        
        if not key_id or key_id not in keys_store or keys_store[key_id].get('type') != 'library':
            return jsonify({'success': False, 'error': 'Clé non trouvée'}), 400
        
        private_key = keys_store[key_id]['private_key']
        signature = private_key.sign(message.encode('utf-8'), hashes.SHA256())
        
        sig_id = str(int(time.time()))
        signatures_store[sig_id] = {
            'message': message,
            'signature': signature,
            'key_id': key_id,
            'type': 'library'
        }
        
        return jsonify({
            'success': True,
            'sig_id': sig_id,
            'signature_hex': signature.hex()
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/library-verify', methods=['POST'])
def library_verify():
    try:
        data = request.json
        key_id = data.get('key_id')
        message = data.get('message')
        signature_hex = data.get('signature_hex')
        
        if not key_id or key_id not in keys_store or keys_store[key_id].get('type') != 'library':
            return jsonify({'success': False, 'error': 'Clé non trouvée'}), 400
        
        public_key = keys_store[key_id]['public_key']
        signature = bytes.fromhex(signature_hex)
        
        try:
            public_key.verify(signature, message.encode('utf-8'), hashes.SHA256())
            valid = True
        except InvalidSignature:
            valid = False
        
        return jsonify({
            'success': True,
            'valid': valid
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
