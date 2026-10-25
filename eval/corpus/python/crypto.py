import hashlib
import random
import secrets

from Crypto.Cipher import AES, DES


def vuln_des(key, data):
    return DES.new(key, DES.MODE_ECB).encrypt(data)  # expect: CM-C001


def vuln_ecb(key, data):
    return AES.new(key, AES.MODE_ECB).encrypt(data)  # expect: CM-C001


def safe_gcm(key, data):
    cipher = AES.new(key, AES.MODE_GCM)
    return cipher.encrypt_and_digest(data)


def vuln_reset_token():
    return "".join(random.choice("abcdef0123456789") for _ in range(32))  # expect: CM-C002


def vuln_otp():
    otp = random.randint(100000, 999999)  # expect: CM-C002
    return otp


def safe_token():
    return secrets.token_urlsafe(32)


def safe_shuffle(items):
    random.shuffle(items)
    return random.choice(items)


def safe_etag(body):
    # lookalike: MD5 used as a cache key, nothing sensitive involved
    return hashlib.md5(body).hexdigest()
