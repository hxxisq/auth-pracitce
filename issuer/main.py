import base64

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI

app = FastAPI()


@app.get("/health")
def health():
    return {"service": "issuer"}


# ---------------------------------------------------------------------------
# Step 1: the user and the password check
# ---------------------------------------------------------------------------

USER = {
    "id": "46d5cb17-aa7a-4079-83a4-9d23d8e8e39f",
    "email": "bruhh@gmail.com",
    "password_hash": "$argon2id$v=19$m=65536,t=3,p=4$TPjqH6ZCrhd6KXvyFyiuag$qyLFzq8gw9SVIbCATgJOq1426WDPcj+kI3b3puyjytM",
}

ph = PasswordHasher()


def check_password(email, password):
    if email != USER["email"]:
        return False
    try:
        return ph.verify(USER["password_hash"], password)
    except VerifyMismatchError:
        return False


# ---------------------------------------------------------------------------
# Step 2: the signing key and the JWKS
# ---------------------------------------------------------------------------

# The private key: ONLY the issuer ever holds this (Supabase's role).
# It's generated fresh every time the server starts. Remember that for "Break it".
PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())  # SECP256R1 = P-256
PUBLIC_KEY = PRIVATE_KEY.public_key()                  # derived from the private key
KID = "key-1"                                          # the key's name, goes in every token header


def b64url(data: bytes) -> str:
    """bytes -> base64url text with no '=' padding (the reverse of Step 0)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def public_key_as_jwk():
    """A P-256 public key is just a point (x, y) on the curve. Publish both numbers."""
    numbers = PUBLIC_KEY.public_numbers()
    return {
        "kty": "EC",        # key type: elliptic curve
        "crv": "P-256",     # which curve
        "alg": "ES256",     # what it's used with
        "use": "sig",       # used for signatures
        "kid": KID,
        "x": b64url(numbers.x.to_bytes(32, "big")),
        "y": b64url(numbers.y.to_bytes(32, "big")),
    }


@app.get("/.well-known/jwks.json")
def jwks():
    # A list, because during key rotation there can be two keys at once (Step 7).
    return {"keys": [public_key_as_jwk()]}
