import hashlib
import json

import jwt
from flask import request


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # expect: CM-D002


def register(db, email):
    db.save({"email": email, "password": request.form["password"]})  # expect: CM-D003


def issue(payload):
    return jwt.encode(payload, "my-jwt-signing-secret", algorithm="HS256")  # expect: CM-D004


def set_session(resp, sid):
    resp.set_cookie("session", sid)  # expect: CM-D005


def dump(users, out_file):
    with open(out_file, "w") as fh:
        fh.write(json.dumps(users))  # expect: CM-D006


def etag(body):
    return hashlib.md5(body).hexdigest()


def safe_cookie(resp, sid):
    resp.set_cookie("session", sid, httponly=True, secure=True, samesite="Lax")


def safe_issue(payload, key):
    return jwt.encode(payload, key, algorithm="HS256")


def safe_register(db, email):
    db.save({"email": email, "password_hash": hash_pw(request.form["password"])})
