# Educational DSA demo. PEM keys (dsa_private.pem / dsa_public.pem) are generated
# locally when you run this script and must never be committed to git.
# The main interactive demo is the static GitHub Pages site at the repo root.

import sympy
import random
import hashlib
import time

from cryptography.hazmat.primitives.asymmetric.dsa import generate_parameters
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


# PARTIE 1 : Génération des clés DSA (implémentation manuelle)

def generate_p(interval_min=20000, interval_max=100000):
    return sympy.randprime(interval_min, interval_max)

def generate_q(p, min_value=50):
    p_devisors = sympy.divisors(p-1)
    prime_devisors = []
    for value in p_devisors:
        if sympy.isprime(value) and value > min_value:
            prime_devisors.append(value)
    if len(prime_devisors) == 0:
        return -1
    else:
        return random.choice(prime_devisors)
    
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


# PARTIE 2 : Signature et vérification DSA (implémentation manuelle)

def get_signature(message, p, q, alpha, d):
    hash_hex = hashlib.sha256(message.encode('utf-8')).hexdigest()
    hash_int = int(hash_hex, 16)

    found_values = False
    while not found_values:
        k = random.randint(1, q-1)
        r = pow(alpha, k, p)%q
        if r != 0:
            found_values = True
        if found_values:
            k_inv = sympy.mod_inverse(k, q)
            s = (k_inv*(hash_int + d*r))%q
            if s != 0:
                return (r, s)
            else:
                found_values = False

def verify_signature(message, r_s, p, q, alpha, beta):
    r, s = r_s
    if r == 0 or s == 0:
        return -1
    
    hash_hex = hashlib.sha256(message.encode('utf-8')).hexdigest()
    hash_int = int(hash_hex, 16)

    w = sympy.mod_inverse(s, q)
    
    u1 = (hash_int*w)%q
    u2 = (r*w)%q

    p_mod_alpha = pow(alpha, u1, p)
    p_mod_beta = pow(beta, u2, p)
    p_mod_AlphaBeta = (p_mod_alpha*p_mod_beta)%p
    v = p_mod_AlphaBeta%q

    return v==r


# DÉMONSTRATION — Alice signe, Bob vérifie

print("=" * 60)
print("PARTIE 1 & 2 — Implémentation manuelle DSA")
print("=" * 60)

# Génération des paramètres
while True:
    p = generate_p()
    q = generate_q(p)
    if q != -1:
        break

alpha = generate_alpha(p, q)
d     = generate_private_key(q)
beta  = calculate_public_key(alpha=alpha, d=d, p=p)

print(f"\nClé publique  kpub = (p, q, α, β)")
print(f"  p     = {p}")
print(f"  q     = {q}")
print(f"  alpha = {alpha}")
print(f"  beta  = {beta}")
print(f"\nClé privée d = {d}")

# Alice signe deux messages
message_alice   = "Bonjour Bob, je suis Alice."
message_modifie = "Bonjour Bob, je suis Eve."

print(f"\n--- Alice signe le message original ---")
print(f"Message : \"{message_alice}\"")
signature = get_signature(message=message_alice, p=p, q=q, alpha=alpha, d=d)
print(f"Signature (r, s) = {signature}")

# Bob vérifie
print(f"\n--- Bob vérifie ---")
result_original = verify_signature(message_alice, signature, p, q, alpha, beta)
result_modifie  = verify_signature(message_modifie, signature, p, q, alpha, beta)

print(f"Vérification message original :")
print(f"({message_alice})")
print(f"Resltat : {result_original}")
print()
print(f"Vérification message modifié :")
print(f"({message_modifie})")
print(f"Resltat : {result_modifie}")


# PARTIE 3 : Utilisation de la bibliothèque cryptography

print("\n" + "=" * 60)
print("PARTIE 3.1 — Génération des clés DSA (bibliothèque cryptography)")
print("=" * 60)

# Génération de la paire de clés DSA (1024 bits pour ce TP)
params      = generate_parameters(key_size=1024, backend=default_backend())
private_key = params.generate_private_key()
public_key  = private_key.public_key()

# Sauvegarde au format PEM
with open("dsa_private.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open("dsa_public.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("Clé privée sauvegardée : dsa_private.pem")
print("Clé publique sauvegardée : dsa_public.pem")

with open("dsa_private.pem") as f:
    print("\nAperçu clé privée :\n" + f.read()[:120] + "...\n")
with open("dsa_public.pem") as f:
    print("Aperçu clé publique :\n" + f.read()[:120] + "...\n")

# -----------------------------------------------------------------------------
print("=" * 60)
print("PARTIE 3.2 — Signature / Vérification (bibliothèque cryptography)")
print("=" * 60)

message_bytes = b"Bonjour Bob, je suis Alice."

# Signature avec la clé privée
signature_lib = private_key.sign(message_bytes, hashes.SHA256())
print(f'signature de message : {message_bytes}')
print(f"Signature générée (hex) : {signature_lib.hex()[:60]}...")

print()
# Vérification — message identique
try:
    print(f'verification de message : {message_bytes}')
    public_key.verify(signature_lib, message_bytes, hashes.SHA256())
    print("Vérification message original  : True")
except InvalidSignature:
    print("Vérification message original  : False")

print()
# Vérification — message falsifié
try:
    message_bytes_modifie = b"Bonjour Bob, je suis Eve."
    print(f'verification de message : {message_bytes_modifie}')
    public_key.verify(signature_lib, message_bytes_modifie, hashes.SHA256())
    print("Vérification message falsifié  : True")
except InvalidSignature:
    print("Vérification message falsifié  : False (détection correcte)")

# -----------------------------------------------------------------------------
print("\n" + "=" * 60)
print("PARTIE 3.3 — Comparaison manuelle vs bibliothèque cryptography")
print("=" * 60)

# Temps d'exécution
print("\n[ Temps d'exécution ]")

t0 = time.perf_counter()
while True:
    p_t = generate_p()
    q_t = generate_q(p_t)
    if q_t != -1:
        break
alpha_t = generate_alpha(p_t, q_t)
d_t     = generate_private_key(q_t)
beta_t  = calculate_public_key(alpha_t, d_t, p_t)
sig_t   = get_signature("hello world", p_t, q_t, alpha_t, d_t)
verify_signature("hello world", sig_t, p_t, q_t, alpha_t, beta_t)
t_manuel = time.perf_counter() - t0

t0 = time.perf_counter()
params2  = generate_parameters(key_size=1024, backend=default_backend())
priv2    = params2.generate_private_key()
pub2     = priv2.public_key()
sig2     = priv2.sign(b"hello world", hashes.SHA256())
pub2.verify(sig2, b"hello world", hashes.SHA256())
t_crypto = time.perf_counter() - t0

print(f"Manuel        : {t_manuel:.4f} sec  (petits paramètres non sécurisés)")
print(f"cryptography  : {t_crypto:.4f} sec  (clés 1024 bits, niveau production)")
print()
