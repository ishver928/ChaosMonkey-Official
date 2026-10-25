import hashlib


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


def verify(password, stored):
    return hashlib.sha1(password.encode()).hexdigest() == stored


class Account:
    def set_password(self, password):
        self.password_hash = hashlib.md5(password.encode()).hexdigest()
