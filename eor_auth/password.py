import random

from passlib.context import CryptContext


# https://pythonhosted.org/passlib/
# TODO support better kdfs?
passlib_context = CryptContext(
    schemes=["pbkdf2_sha256"],
    default="pbkdf2_sha256",
    all__vary_rounds = 0.1,
    pbkdf2_sha256__default_rounds = 8000,
)


# TODO configurable - settings for password generation
PWD_CHARACTERS = '23456qwertasdfgzxcvbQWERTASDFGZXCVB789yuiophjknmYUIPHJKLNM'
MIN_PWD_LEN = 6
MAX_PWD_LEN = 9


def check_password(password, hash):
    try:
        return passlib_context.verify(password, hash)
    except ValueError:  # "hash could not be identified" (e.g. hash is empty)
        return False


def hash_password(password):
    return passlib_context.encrypt(password)


def generate_confirm_code():
    bytes = 16
    return hex(random.getrandbits(bytes*8))[2:-1]


def generate_password():
    return ''.join([
        random.choice(self.PWD_CHARACTERS) for i in range(random.randint(self.MIN_PWD_LEN, self.MAX_PWD_LEN))
    ])
