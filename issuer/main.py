from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
def health():
    return {"service":"issuer"}



USER = {
    "id" : "46d5cb17-aa7a-4079-83a4-9d23d8e8e39f",
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
